import re
from pathlib import Path

# Safety limits to prevent scanning entire filesystems.
_MAX_RESULTS = 200
_MAX_FILES_SCANNED = 50_000
_MAX_SIMILAR = 20


def _similar_score(search_words, filename):
    """Return how many search words appear in the filename (case-insensitive)."""
    name_lower = filename.lower()
    return sum(1 for w in search_words if w in name_lower)


def find_files(directory, name=None, extension=None):
    """Search for files by name or extension with safety limits.

    When a name filter is provided but no exact matches are found,
    a second pass looks for files with partially similar names
    and returns them as suggestions.
    """
    results = []
    scanned = 0
    all_files = []  

    directory = Path(directory)

    if not directory.is_dir():
        return [f"Error: '{directory}' is not a valid directory."]

    for path in directory.rglob("*"):
        scanned += 1

        # Stop scanning if we've checked too many files.
        if scanned >= _MAX_FILES_SCANNED:
            results.append(
                f"(scan stopped after {_MAX_FILES_SCANNED} files — "
                f"try a more specific directory)"
            )
            break

        if not path.is_file():
            continue

        # Track files for fuzzy fallback when name filter is active.
        if name and not results:
            all_files.append(path)

        if name and name.lower() not in path.name.lower():
            continue

        if extension and path.suffix.lower() != extension.lower():
            continue

        results.append(str(path))

        if len(results) >= _MAX_RESULTS:
            results.append(
                f"(results capped at {_MAX_RESULTS} — "
                f"try a more specific search)"
            )
            break

    # ---------------------------------------------------------
    # FUZZY FALLBACK: suggest similar files when no exact match.
    # ---------------------------------------------------------
    if not results and name:
        # Split the search term into words for partial matching.
        search_words = [
            w for w in re.split(r"[_\-\s.]+", name.lower()) if len(w) >= 2
        ]

        if search_words:
            scored = []
            for path in all_files:
                score = _similar_score(search_words, path.name)
                if score > 0:
                    scored.append((score, str(path)))

            # Sort by score descending, take top results.
            scored.sort(key=lambda x: x[0], reverse=True)
            similar = [path for _, path in scored[:_MAX_SIMILAR]]

            if similar:
                results.append(
                    f"No exact match for '{name}' was found, "
                    f"but these files have similar names:"
                )
                results.extend(similar)
            else:
                results.append(
                    f"No files matching '{name}' were found "
                    f"in '{directory}'."
                )
        else:
            results.append(
                f"No files matching '{name}' were found "
                f"in '{directory}'."
            )

    return results


def search_text_file(path, query):
    """Search a single text file for lines matching a query."""
    matches = []
    path = Path(path)

    if not path.is_file():
        return [{"error": f"'{path}' is not a valid file."}]

    try:
        with open(path, "r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                if query.lower() in line.lower():
                    matches.append({
                        "line_number": line_number,
                        "text": line.strip()
                    })

                # Cap matches to avoid huge outputs.
                if len(matches) >= 50:
                    break

    except (UnicodeDecodeError, PermissionError, OSError):
        pass

    return matches


def search_files_by_content(directory, query):
    """Search all files in a directory for content matching a query."""
    results = []
    files = find_files(directory)

    for file in files:
        matches = search_text_file(file, query)

        if matches:
            results.append({
                "file": file,
                "matches": matches
            })

        if len(results) >= 20:
            break

    return results
