#!/bin/sh
set -e


cat <<EOM
 _____________________________________________________________________________
( =========================================================================== )
(  Welcome to Docker RACD ProVerif Container                                  )
( =========================================================================== )
(                                                                             )
( ProVerif is installed under '/opt/proverif/'.                               )
( The executable 'proverif' is available in the PATH.                         )
(                                                                             )
( Execute the following command to run RACD ProVerif code:                    )
(                                                                             )
(    proverif racd.pv                                                         )
(                                                                             )
(_____________________________________________________________________________)
        \\
         \\              ##        .
          \\       ## ## ##       ==
               ## ## ## ##      ===
           /""""""""""""""""___/ ===
      ~~~ {~~ ~~~~ ~~~ ~~~~ ~~ ~ /  ===- ~~~
           \______ o ____     __/
            \    \  |RACD| __/
             \____\_______/

EOM


exec "$@"

