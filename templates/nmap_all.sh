set -e

files=$(ls | grep "nmap-sg")

for file in $files; do
  echo $file
  ./$file
done
