filename=$1

scp -r ./$filename ssy@bf1:~/deltaint/DeltaINT-O/Tofino/C1/$filename
scp -r ./$filename ssy@dl13:~/projects/deltaint/DeltaINT-O/Tofino/C1/$filename
