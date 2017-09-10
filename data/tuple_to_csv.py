
'''
import csv

csv.register_dialect("custom", delimiter=",", skipinitialspace=True)
x = open('asked_result.tuple', 'r').read().split('\n')[:-1]
with open('asked_result.csv', "w") as the_file:
    writer = csv.writer(the_file, dialect="custom")
    for tup in x:
        print(tup)
        writer.writerow(eval(tup))
'''
import csv

x = open('asked_result.tuple', 'r').read().split('\n')[:-1]
with open('text.csv', 'w', newline="") as csvfile:
    fwriter = csv.writer(csvfile)
    for i in x:
        print(i)
        fwriter.writerow(eval(i))
