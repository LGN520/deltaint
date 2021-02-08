#python3 fct_analysis.py -p fct_fat_wb50_b100 -s 5 -t 0 -T 2200000000 -b 100 > fct_wb50_dint_mi0_log1.05_vs_pint.dat
#python3 plotDINTVsPINT.py -d wb

python3 fct_analysis.py -p fct_fat_fb50_b100 -s 5 -t 0 -T 2200000000 -b 100 > fct_fb50_dint_mi0_log1.05_vs_pint.dat
python3 plotDINTVsPINT.py -d fb
