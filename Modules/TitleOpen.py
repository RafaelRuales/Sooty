import random
import os

os.system("")


class style:
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

print(style.YELLOW + "Hello, World!")

def titleOpen():
    var = random.randint(1,2)
    if var == 1:
        print('''                                           
 @@@@@@    @@@@@@    @@@@@@   @@@@@@@  @@@ @@@  
@@@@@@@   @@@@@@@@  @@@@@@@@  @@@@@@@  @@@ @@@  
!@@       @@!  @@@  @@!  @@@    @@!    @@! !@@  
!@!       !@!  @!@  !@!  @!@    !@!    !@! @!!  
!!@@!!    @!@  !@!  @!@  !@!    @!!     !@!@!   
 !!@!!!   !@!  !!!  !@!  !!!    !!!      @!!!   
     !:!  !!:  !!!  !!:  !!!    !!:      !!:    
    !:!   :!:  !:!  :!:  !:!    :!:      :!:    
:::: ::   ::::: ::  ::::: ::     ::       ::    
:: : :     : :  :    : :  :      :        :    
 
                           by @TheresAFewConors''')
    if var == 2:
        print('''

   _____             _         
  / ____|           | |        
 | (___   ___   ___ | |_ _   _ 
  \___ \ / _ \ / _ \| __| | | |
  ____) | (_) | (_) | |_| |_| |
 |_____/ \___/ \___/ \__|\__, |
                          __/ |
                         |___/ 
                         
                            by @TheresAFewConors
''')
    print("\n The SOC Analyst's all-in-one tool to "
          "automate and speed up workflow ")
    input('\n Press Enter to continue..')
