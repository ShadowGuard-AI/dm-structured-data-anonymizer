import argparse
import json
import csv
import xml.etree.ElementTree as ET
import re
import logging
import random
import sys
from faker import Faker
import os
from pathlib import Path

class UnsafeRuleError(ValueError):
    pass

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class DataAnonymizer:
    """
    Anonymizes structured data formats (JSON, CSV, XML) by applying configurable masking rules to specific fields.
    """

    def __init__(self, config_file=None):
        """
        Initializes the DataAnonymizer with an optional configuration file.

        Args:
            config_file (str, optional): Path to the configuration file. Defaults to None.
        """
        self.config = self._load_config(config_file) if config_file else {}
        self.fake = Faker()
        self.replacement_count = 0

    def _load_config(self, config_file):
        """
        Loads the configuration from a JSON file.

        Args:
            config_file (str): Path to the configuration file.

        Returns:
            dict: The configuration as a dictionary.

        Raises:
            FileNotFoundError: If the configuration file is not found.
            json.JSONDecodeError: If the configuration file is not valid JSON.
        """
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            logging.info(f"Configuration loaded from {config_file}")
            return config
        except FileNotFoundError as e:
            logging.error(f"Configuration file not found: {e}")
            raise
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON in configuration file: {e}")
            raise

    def anonymize_json(self, data, config=None):
        """
        Anonymizes JSON data based on the provided configuration or the class configuration.

        Args:
            data (dict): The JSON data to anonymize.
            config (dict, optional): Anonymization rules. Defaults to None.

        Returns:
            dict: The anonymized JSON data.
        """
        config = config or self.config
        return self._anonymize_data(data, config)

    def anonymize_csv(self, data, config=None):
        """
        Anonymizes CSV data based on the provided configuration or the class configuration.

        Args:
            data (list of dict): The CSV data to anonymize (represented as a list of dictionaries).
            config (dict, optional): Anonymization rules. Defaults to None.

        Returns:
            list of dict: The anonymized CSV data.
        """
        config = config or self.config
        anonymized_data = []
        for row in data:
            anonymized_data.append(self._anonymize_data(row, config))
        return anonymized_data

    def anonymize_xml(self, xml_string, config=None):
         """
         Anonymizes XML data based on the provided configuration or the class configuration.

         Args:
             xml_string (str): The XML data as a string.
             config (dict, optional): Anonymization rules. Defaults to None.

         Returns:
             str: The anonymized XML data as a string.
         """
         config = config or self.config
         try:
             root = ET.fromstring(xml_string)
             self._anonymize_xml_element(root, config)
             return ET.tostring(root, encoding='utf8').decode('utf8')
         except ET.ParseError as e:
             logging.error(f"Error parsing XML: {e}")
             raise

    def _anonymize_xml_element(self, element, config):
        """
        Recursively anonymizes an XML element based on the configuration.

        Args:
            element (xml.etree.ElementTree.Element): The XML element to anonymize.
            config (dict): Anonymization rules.
        """
        # XML is narrower than JSON here in two ways I keep visible: only
        # element text is ever replaced, never an attribute, so a value in
        # an attribute named in the config sails through untouched; and the
        # root element itself is never tested against the config, only its
        # descendants are. Replacing the text of an element that has child
        # elements leaves those children in place, and the recursion still
        # visits them after the parent's text has been swapped.
        for child in element:
            if child.tag in config:
                rule = config[child.tag]
                child.text = self._apply_masking_rule(rule)
                self.replacement_count += 1
            self._anonymize_xml_element(child, config)



    def _anonymize_data(self, data, config):
        """
        Anonymizes a dictionary (used for both JSON and CSV rows) based on the configuration.

        Args:
            data (dict): The data to anonymize.
            config (dict): Anonymization rules.

        Returns:
            dict: The anonymized data.
        """
        # Top-level JSON is often a list of records (the examples at the
        # bottom of this file show exactly that shape), not one object.
        # Recursing into list items keeps that input working instead of
        # failing on data.items().
        if isinstance(data, list):
            return [self._anonymize_data(item, config) for item in data]
        if not isinstance(data, dict):
            return data
        anonymized_data = {}
        for key, value in data.items():
            # A rule matches on the key name alone, at any depth, and the
            # rule check comes before the recursion below: a ruled key whose
            # value is a whole nested object is replaced by one flat masking
            # value, and the structure under it is gone. The count also goes
            # up whatever _apply_masking_rule returns, including its
            # [MASKING_ERROR] fallback, so the count in main measures rules
            # attempted, not values successfully hidden.
            rule = config.get(key)
            if rule:
                anonymized_data[key] = self._apply_masking_rule(rule)
                self.replacement_count += 1
            elif isinstance(value, dict):
                anonymized_data[key] = self._anonymize_data(value, config)
            elif isinstance(value, list):
                anonymized_data[key] = [self._anonymize_data(item, config) if isinstance(item, (dict, list)) else item for item in value]
            else:
                anonymized_data[key] = value  # Keep original value if no rule is defined
        return anonymized_data

    def _apply_masking_rule(self, rule):
        """
        Applies a specific masking rule based on the configuration.

        Args:
            rule (str): The masking rule to apply (e.g., "fake.name", "random.randint(1000, 9999)").

        Returns:
            str: The anonymized value.
        """
        try:
            if rule.startswith("fake."):
                fake_attribute = rule[5:]
                return str(getattr(self.fake, fake_attribute)())
            elif rule.startswith("random."):
                match = re.fullmatch(r"random\.randint\(\s*(-?\d+)\s*,\s*(-?\d+)\s*\)", rule)
                if not match:
                    raise UnsafeRuleError(f"Unsupported random rule: {rule}. Only random.randint with two integer bounds is allowed.")
                return str(random.randint(int(match.group(1)), int(match.group(2))))
            elif rule == "null":
                return None  # Or use "null" string representation
            elif rule.startswith("regex:"):
                # Extract the regex and generate a masked value based on the regex pattern
                regex_pattern = rule[6:]
                return self._generate_masked_value_from_regex(regex_pattern)
            else:
                # Any rule string that is not fake., random., null, or
                # regex: is not an error: it becomes the replacement itself,
                # stamped identically on every matching field in the file.
                # A typo in a config therefore does not fail the run; it
                # quietly turns a column into one repeated constant, which
                # can be the intent or can be a config mistake that looks
                # exactly like the intent in the output.
                return rule  # Use the rule as a literal value
        except UnsafeRuleError:
            raise
        except Exception as e:
            logging.error(f"Error applying masking rule '{rule}': {e}")
            return "[MASKING_ERROR]"  # Return an error indicator

    def _generate_masked_value_from_regex(self, regex_pattern):
      """
      Generates a masked value based on the provided regex pattern.

      Args:
          regex_pattern (str): The regex pattern to generate a masked value for.

      Returns:
          str: The masked value.
      """
      # Generate a placeholder based on the regex.  This is a simple example and 
      # can be expanded to handle more complex regex patterns.
      if regex_pattern == r"^\d{3}-\d{2}-\d{4}$":  # Example: Social Security Number
          return self.fake.ssn()
      elif regex_pattern == r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$": #Example: Email
          return self.fake.email()
      elif regex_pattern == r"^\d{10}$":  # Example: Phone number
          return self.fake.phone_number()

      else:
          # If the regex pattern is not recognized, return a default masked value
          return "[MASKED_VALUE]"



def setup_argparse():
    """
    Sets up the command-line argument parser.

    Returns:
        argparse.ArgumentParser: The argument parser.
    """
    parser = argparse.ArgumentParser(description='Anonymize structured data (JSON, CSV, XML).')
    parser.add_argument('input_file', help='Path to the input file.')
    parser.add_argument('output_file', help='Path to the output file.')
    parser.add_argument('--config', help='Path to the configuration file (JSON).', required=True)
    parser.add_argument('--format', choices=['json', 'csv', 'xml'], required=True, help='Data format (json, csv, xml).')
    return parser

def main():
    """
    Main function to parse arguments, load data, anonymize, and write the anonymized data to a file.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if Path(args.input_file).resolve() == Path(args.output_file).resolve():
        print("Error: Output file must not be the same as the input file.")
        sys.exit(1)
    try:
        anonymizer = DataAnonymizer(args.config)

        with open(args.input_file, 'r') as f:
            if args.format == 'json':
                try:
                    data = json.load(f)
                    anonymized_data = anonymizer.anonymize_json(data)
                except json.JSONDecodeError as e:
                    logging.error(f"Error decoding JSON from input file: {e}")
                    print(f"Error decoding JSON from input file: {e}")
                    sys.exit(1)
            elif args.format == 'csv':
                reader = csv.DictReader(f)
                data = list(reader)
                anonymized_data = anonymizer.anonymize_csv(data)
            elif args.format == 'xml':
                xml_string = f.read()
                anonymized_data = anonymizer.anonymize_xml(xml_string)
            else:
                print("Unsupported format.")
                sys.exit(1)

        if getattr(anonymizer, "replacement_count", 0) == 0:
            logging.error("No fields anonymized.")
            print("No fields anonymized.")
            sys.exit(1)
        with open(args.output_file, 'w') as f:
            if args.format == 'json':
                json.dump(anonymized_data, f, indent=4)
            elif args.format == 'csv':
                if anonymized_data:
                    writer = csv.DictWriter(f, fieldnames=anonymized_data[0].keys())
                    writer.writeheader()
                    writer.writerows(anonymized_data)
                else:
                    # An empty input still gets its header row, so the
                    # output stays a valid CSV with the same columns
                    # instead of a zero byte file.
                    writer = csv.DictWriter(f, fieldnames=reader.fieldnames or [])
                    writer.writeheader()
            elif args.format == 'xml':
                f.write(anonymized_data)

        logging.info(f"Anonymized data written to {args.output_file}")
        print(f"Anonymized data written to {args.output_file}")

    except FileNotFoundError as e:
        logging.error(e)
        print(e)
        # Exit non-zero on failure. Every error path in main used to
        # return normally, so a missing input file or an unparseable
        # JSON document still reported success to the shell.
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()


# Example Usage:
# 1. Create a config.json file with anonymization rules (see example below).
# 2. Create an input file (e.g., data.json, data.csv, data.xml).
# 3. Run the script:
#    python main.py data.json output.json --config config.json --format json
#    python main.py data.csv output.csv --config config.json --format csv
#    python main.py data.xml output.xml --config config.json --format xml

# Example config.json:
# {
#   "name": "fake.name",
#   "email": "fake.email",
#   "age": "random.randint(18, 65)",
#   "phone": "fake.phone_number",
#   "ssn": "regex:^\\d{3}-\\d{2}-\\d{4}$"
# }

# Example XML config.json
# {
#   "name": "fake.name",
#   "email": "fake.email"
# }

#Example Input data.json:
# [
#     {
#         "name": "John Doe",
#         "email": "john.doe@example.com",
#         "age": 30,
#         "phone": "555-123-4567",
#         "ssn": "123-45-6789"
#     },
#     {
#         "name": "Jane Smith",
#         "email": "jane.smith@example.com",
#         "age": 25,
#         "phone": "555-987-6543",
#         "ssn": "987-65-4321"
#     }
# ]

#Example Input data.csv
# name,email,age,phone,ssn
# John Doe,john.doe@example.com,30,555-123-4567,123-45-6789
# Jane Smith,jane.smith@example.com,25,555-987-6543,987-65-4321

# Example input data.xml
# <root>
#     <person>
#         <name>John Doe</name>
#         <email>john.doe@example.com</email>
#     </person>
#     <person>
#         <name>Jane Smith</name>
#         <email>jane.smith@example.com</email>
#     </person>
# </root>