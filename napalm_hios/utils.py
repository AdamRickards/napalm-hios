import logging
import re


def log_error(logger, message):
    """
    Utility function to log errors consistently across the driver.
    """
    logger.error(message)


def parse_dot_keys(text):
    """
    Parse HiOS dot-separated key-value output.

    Lines like:
        System name.................................GRS1042-CORE
        Current temperature.........................50 C

    Returns dict of {key: value} with leading/trailing dots stripped.
    Non-matching lines are silently skipped.
    """
    result = {}
    for line in text.splitlines():
        if '....' not in line:
            continue
        key, _, value = line.partition('....')
        key = key.strip()
        value = value.strip().lstrip('.')
        if key:
            result[key] = value
    return result


def parse_table(text, min_fields=2):
    """
    Parse a HiOS fixed-width table with a dashed separator line.

    Splits on the first `-----` separator. Everything after is data.
    Skips blank lines and lines that are entirely dashes.
    Each row is returned as a list of whitespace-split fields.

    Args:
        text: raw CLI output string
        min_fields: minimum number of fields for a row to be included

    Returns:
        list of lists, one per data row
    """
    rows = []
    past_header = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Detect separator line
        if re.match(r'^[-\s]+$', stripped) and '---' in stripped:
            past_header = True
            continue
        if not past_header:
            continue
        fields = stripped.split()
        if len(fields) >= min_fields:
            rows.append(fields)
    return rows


def parse_multiline_table(text, lines_per_record, min_fields_first=2):
    """
    Parse a HiOS table where each record spans multiple lines.

    Example: show port (2 lines per interface), show interface counters
    (3 lines per interface), show users (2 lines per user).

    Args:
        text: raw CLI output string
        lines_per_record: number of lines per logical record
        min_fields_first: minimum fields on the first line to start a record

    Returns:
        list of tuples, each containing `lines_per_record` field-lists.
        Secondary lines that don't have enough content are returned as
        empty lists.
    """
    rows = parse_table(text, min_fields=1)

    records = []
    i = 0
    while i < len(rows):
        first = rows[i]
        # Check if this looks like the start of a record (has interface-like
        # first field with enough columns)
        if len(first) >= min_fields_first and '/' in first[0]:
            record = [first]
            for j in range(1, lines_per_record):
                if i + j < len(rows) and (not rows[i + j] or '/' not in rows[i + j][0]):
                    record.append(rows[i + j])
                else:
                    record.append([])
            records.append(tuple(record))
            i += lines_per_record
        else:
            i += 1

    return records
