set -e

files=$(ls | grep "nmap-sg")

for file in $files; do
  ./$file
done
