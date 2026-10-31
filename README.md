![Banner](banner.png)

# dm-structured-data-anonymizer
Anonymizes structured data formats (JSON, CSV, XML) by applying configurable masking rules to specific fields based on field name or regex pattern matching. Supports loading rules from a configuration file. - Focused on Tools designed to generate or mask sensitive data with realistic-looking but meaningless values

## Install
`git clone https://github.com/ShadowStrikeHQ/dm-structured-data-anonymizer`

## Usage
`./dm-structured-data-anonymizer [params]`

## Parameters
- `-h`: Show help message and exit
- `--config`: No description provided
- `--format`: No description provided

## License
Copyright (c) ShadowStrikeHQ

The method is per field substitution: a field whose name has a rule in the config is replaced, at any depth. Nested objects and lists are walked, as XML elements already were, so a named field inside a nested object or a list is replaced in the same way as a top level field. No anonymization model is computed: the tool does not calculate k-anonymity or any similar measure, and fields with no rule pass through unchanged.
The output file must not be the same file as the input file. A run that names the same file for both is refused and nothing is written.
A run that replaces no fields exits with an error, prints a plain no fields anonymized line, and writes no output file.
Config rules that start with random. are not evaluated as code. The only accepted form is random.randint with two integer bounds, for example random.randint(18, 65), which is the form the shipped examples use. Any other random. rule is rejected and the run exits with an error.
