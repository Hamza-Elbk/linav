# TODO 1: Create a function called show_help that prints how to use the script.
# Example: show required options -s and -d, and optional -c and -h.

# TODO 2: Set default values for your variables
# - compress should default to false
# - source_dir and dest_dir should be empty

# TODO 3: Start a while loop to parse options using getopts
# Use ":s:d:ch" as the option string (meaning -s and -d need arguments, -c and -h are flags)

# TODO 4: Inside the loop, use a case statement to handle each option:
# - If opt is 's', set source_dir to $OPTARG
# - If opt is 'd', set dest_dir to $OPTARG
# - If opt is 'c', set compress to true
# - If opt is 'h', call show_help and exit
# - If opt is missing an argument (":" case), print an error and show help
# - If opt is invalid ("?" case), print an error and show helpH

# TODO 5: After the loop, check if source_dir or dest_dir is empty.
# If either is missing, print an error and show the help message, then exit.

# TODO 6: Simulate the backup process.
# - Print a message that you're backing up from source_dir to dest_dir
# - If compress is true, print "Compressing backup..."
# - Otherwise, print "No compression."

usage(){
  echo "Usage: $0 -s <source> -d <destination> [-c] [-h]"
  echo "  -s    Source directory (required)"
  echo "  -d    Destination directory (required)"
  echo "  -c    Compress the backup"
  echo "  -h    Show help"
}
usage