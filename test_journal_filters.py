from sympy.parsing.sympy_parser import parse_expr
from sympy import Symbol
import configparser
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List

def evaluate_filter_with_sympy(filter_str: str, event_text: str, debug: bool = False, matches: dict = None) -> bool:
    """
    Evaluate a logical filter string against event text using sympy.
    Shows which parts of the filter matched.
    """
    try:
        # Create a valid symbol name for each term
        terms_map = {}
        counter = 0
        
        # First, preserve quoted strings
        parts = filter_str.split('"')
        processed_terms = []
        
        for i, part in enumerate(parts):
            if i % 2 == 0:  # Outside quotes
                processed_terms.append(part)
            else:  # Inside quotes
                symbol_name = f"term_{counter}"
                terms_map[symbol_name] = part
                processed_terms.append(symbol_name)
                counter += 1
        
        # Rejoin and convert operators
        filter_str = ''.join(processed_terms)
        filter_str = (filter_str.replace(' and ', ' & ')
                               .replace(' or ', ' | ')
                               .replace('not ', '~')
                               .replace('(', ' ( ')
                               .replace(')', ' ) ')
                               .strip())
        
        # Handle 'not(' case specifically
        filter_str = filter_str.replace('~(', '~ (')
        
        # Ensure proper spacing around operators
        filter_str = ' '.join(token for token in filter_str.split() if token)
        
        # Add parentheses if needed
        if '|' in filter_str and '&' in filter_str and not filter_str.startswith('('):
            filter_str = f"({filter_str})"
        
        # Create symbols and truth values
        event_text = event_text.lower()
        symbols = {}
        truth_values = {}
        match_results = {}
        
        # Handle terms from the mapping
        for symbol_name, term in terms_map.items():
            symbols[symbol_name] = Symbol(symbol_name)
            is_match = term.lower() in event_text
            truth_values[symbols[symbol_name]] = is_match
            match_results[term] = is_match
        
        if matches is not None:
            matches.clear()
            matches.update(match_results)
        
        # Print match details if there's a match
        # if result:
        #     print("\nMatch details:")
        #     print(f"Log entry: {event_text[:100]}...")
        #     print("Terms matched:")
        #     for term, did_match in matches.items():
        #         if did_match:
        #             print(f"  ✓ '{term}'")
        #         else:
        #             print(f"  ✗ '{term}'")
        #     print("-" * 40)

        expr = parse_expr(filter_str, evaluate=False)
        return bool(expr.subs(truth_values))
        
    except Exception as e:
        if debug:
            print(f"Error parsing filter '{filter_str}': {e}")
            print(f"Event text: {event_text}")
        return False

def load_journal_filters(config_path: str) -> Dict[str, dict]:
    """
    Load monitoring filters from config file.
    
    Args:
        config_path: Path to config file
    Returns:
        Dictionary of filter configurations
    """
    config = configparser.ConfigParser()
    config.read(config_path)
    
    return {
        key.replace('.filters', ''): {
            'title': config['JournalMonitoring'].get(f'{key.replace(".filters", "")}.title', key),
            'filter': config['JournalMonitoring'][key]
        }
        for key in config['JournalMonitoring']
        if key.endswith('.filters')
    }

def get_journal_logs(hours: int = 24) -> List[str]:
    """
    Get journald logs from specified time period.
    
    Args:
        hours: Number of hours to look back
    Returns:
        List of log entries
    """
    since = (datetime.now() - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
    try:
        result = subprocess.run(
            ['journalctl', '--since', since, '--no-pager'],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.splitlines()
    except subprocess.CalledProcessError as e:
        print(f"Error getting journal logs: {e}")
        return []

def test_filters(filters: Dict[str, dict], logs: List[str]) -> None:
    """
    Test filters against logs and print results with match details.
    """
    print(f"Testing {len(filters)} filters against {len(logs)} log entries\n")
    
    for event_name, filter_data in filters.items():
        match_groups = {
            'login_related': [],
            'auth_failure': [],
            'invalid_user': [],
            'system_events': [],
            'other': []
        }
        
        # Track matches and their details for each category
        match_details = {category: {} for category in match_groups}
        
        for log in logs:
            matches = {}
            if evaluate_filter_with_sympy(filter_data['filter'], log, matches=matches):
                log_lower = log.lower()
                # Categorize and store match details
                if 'authentication failure' in log_lower:
                    match_groups['auth_failure'].append(log)
                    match_details['auth_failure'] = matches
                elif 'invalid user' in log_lower:
                    match_groups['invalid_user'].append(log)
                    match_details['invalid_user'] = matches
                elif 'systemd-logind' in log_lower:
                    match_groups['login_related'].append(log)
                    match_details['login_related'] = matches
                elif any(term in log_lower for term in ['systemd', 'dbus', 'system']):
                    match_groups['system_events'].append(log)
                    match_details['system_events'] = matches
                else:
                    match_groups['other'].append(log)
                    match_details['other'] = matches

        print(f"\n=== {filter_data['title']} ===")
        print(f"Filter: {filter_data['filter']}")
        total_matches = sum(len(matches) for matches in match_groups.values())
        print(f"Total matches found: {total_matches}\n")

        # Print categorized results with match details
        for category, category_matches in match_groups.items():
            if category_matches:
                print(f"\n{category.replace('_', ' ').title()} ({len(category_matches)} matches):")
                # Show first 3 examples
                for match in category_matches[:3]:
                    print(f"  • {match[:100]}...")
                if len(category_matches) > 3:
                    print(f"    ... and {len(category_matches) - 3} more")
                
                # Show match details for this category
                if match_details[category]:
                    print("\nMatch details for this category:")
                    print("Terms matched:")
                    for term, did_match in match_details[category].items():
                        if did_match:
                            print(f"  ✓ '{term}'")
                        else:
                            print(f"  ✗ '{term}'")
                    print("-" * 40)

        print("-" * 60)

def main():
    try:
        filters = load_journal_filters('local_config.ini')
        logs = get_journal_logs(24)
        test_filters(filters, logs)
    except Exception as e:
        print(f"Error running tests: {e}")

if __name__ == "__main__":
    main()