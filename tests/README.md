# NAPALM HiOS Driver Tests

This directory contains the unit tests for the NAPALM HiOS driver.

## Running the Tests

To run the unit tests, follow these steps:

1. Ensure you have the necessary dependencies installed. You can install them using:
   ```
   pip install -r requirements.txt
   ```

2. From the root directory of the project, run:
   ```
   python -m unittest discover tests/unit
   ```

   This command will discover and run all the tests in the `tests/unit` directory.

## Test Structure

- `tests/unit/test_hios_driver.py`: Contains unit tests for the HIOSDriver class.

## Adding New Tests

When adding new functionality to the driver, please ensure that you also add corresponding unit tests. Place new test methods in the appropriate test class in `test_hios_driver.py`.

## Code Coverage

To get a code coverage report, you can use the `coverage` tool:

1. Install coverage:
   ```
   pip install coverage
   ```

2. Run the tests with coverage:
   ```
   coverage run -m unittest discover tests/unit
   ```

3. Generate a coverage report:
   ```
   coverage report -m
   ```

This will show you which parts of the code are covered by the tests and which parts might need additional testing.

## Continuous Integration

These tests are automatically run in our CI/CD pipeline on every push to the repository. Please ensure all tests pass before submitting a pull request.
