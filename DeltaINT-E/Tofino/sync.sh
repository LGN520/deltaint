#DIRNAME="DeltaINT-E/Tofino/C1/"
#DIRNAME="DeltaINT-E/Tofino/C2/"
#DIRNAME="DeltaINT-E/Tofino/C3/"
DIRNAME="DeltaINT-E/Tofino/C4/"
#DIRNAME="DeltaINT-E/Tofino/original_INT/"

ssh ssy@bf1 "rm -rf deltaint/$DIRNAME"
ssh ssy@dl13 "rm -rf projects/deltaint/$DIRNAME"

echo "sync to bf1"
rsync -av -e ssh --exclude "*.pyc" --exclude "*.html" --exclude "*.js" ~/projects/deltaint/$DIRNAME ssy@bf1:~/deltaint/$DIRNAME
echo "sync to dl13"
rsync -av -e ssh --exclude "*.pyc" --exclude "*.html" --exclude "*.js" ~/projects/deltaint/$DIRNAME ssy@dl13:~/projects/deltaint/$DIRNAME
