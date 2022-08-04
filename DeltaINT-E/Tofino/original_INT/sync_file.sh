filename=$1

scp -r ./$filename ssy@bf1:~/deltaint/DeltaINT-E/Tofino/original_INT/$filename
scp -r ./$filename ssy@dl13:~/projects/deltaint/DeltaINT-E/Tofino/original_INT/$filename
