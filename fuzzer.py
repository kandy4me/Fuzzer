import os, random, subprocess, sys
from shutil import copy2
from re import split


## App-to-fuzz
app_local = r"7z934\7za.exe"
app_absolute = os.path.join( os.getcwd(), app_local )


## List of files to use as initial seeds
# source file : RAND's 'a million random digits' via
# www.rand.org/content/dam/rand/pubs/monograph_reports/MR1418/MR1418.digits.txt.zip
file_list = [
    "test_7z.7z",
    "test_gz.gz",
    "test_zip.zip"
    ]


## Fuzz-Test Parameters
numb_tests  = 3 # per-file
fuzz_factor = 250 # maximum number of 'fuzz' iterations per-test
fuzz_output = open( "fuzzlog.txt", 'a' )


### sanity checking
assert os.path.isfile( app_absolute )
for file in file_list :
    
    # assert file exists and is valid
    assert os.path.isfile ( file )
    
    try :
        print ( "Verifying the integrity of seed file {}"
                .format(file) )
        
        retcode = subprocess.check_call ( "{0} t {1}"
                                         .format(app_absolute, file) )
        
        print ( "Returned {}".format(retcode) )
        assert 0 == int(retcode)
    
    except : 
        print ( "Integrity check failed for seed {}\n".format(file) )
    


### fuzzing functionality
def test( app, input_list ) :
    
    def del_byte ( infile, offset ) :
        # new_infile1 = infile [ : (offset-1) ]
        # new_infile2 = infile [ (offset+1) : ]
        #
        # infile = new_infile1 + new_infile2
        #
        # raw_input("Debug 'infile'")
        infile.pop(offset)
    
    
    def add_byte ( infile, offset, inbyte ) :
        # newfile = []
        #
        # for x in range ( len(inbyte)+1 ) :
            
            # if x == offset :
                # newfile[x] = inbyte
            
            # elif x < offset :
                # newfile[x] = infile[x]
            
            # elif x > offset : 
                # newfile[x] = infile[x-1]
        #
        # return newfile
        infile.insert(offset, inbyte)
    
    
    print ( "\n\n<test>\n" )
    app_path, app_name = os.path.split ( app )
    print ( "Fuzzing program {}\n\n".format(app_name) )
    
    for file in input_list :
        print( '<fuzz_seed name="{}"> # using {} as seed'.format(file) )
        
        # get stats for the base file
        file_name, file_ext = split ( '\.', file )
        file_hash  = hash ( file )
        file_stats = os.stat ( file )
        file_size  = file_stats.st_size
        
        # test results
        failure_list = []
        success_list = [] # don't really need...
        
        for i in range(numb_tests) :
            print ( '<test num="{}">'.format(i) )
            
            # copy the 'seed file' and, if successful, fuzz the file
            try:
                fuzzed_file_name = file_name + "_fuzz_" + str(i) + r"." + file_ext
                fuzzed_file_path = os.path.join ( app_path, fuzzed_file_name )
                copy2 ( file, fuzzed_file_path )
                assert hash ( fuzzed_file_path ) == file_hash
            
            except : 
                raw_input ( "<error>There was a problem copying file for fuzzing.</error>" )
            
            else :
                with open ( fuzzed_file_path, 'r+b' ) as fuzz_file :

                    # fuzz iterations, maximum 'fuzz_factor' number of times
                    for n in range ( random.randrange(fuzz_factor) ) :
                        
                        ## modify file based on random numbers
                        
                        # create a random number (0 <= x <= 1)                
                        test_rand_flt = random.random()
                        
                        # choose a random byte within the file
                        random_offset = random.randrange ( file_size )
                        
                        # insert or delete a random byte ~2% of the time 
                        if test_rand_flt <= 0.01 :
                            del_byte ( infile = fuzz_file, 
                                       offset = random_offset )
                        
                        elif test_rand_flt >= 0.99 :
                            add_byte ( infile = fuzz_file, 
                                       offset = random_offset,
                                       inbyte = random.getrandbits(8) )
                        
                        # otherwise, fuzz a random byte within the file
                        else :
                            fuzz_file.seek  ( random_offset )
                            fuzz_file.write ( os.urandom(1) )
                    
                
                # TODO: update checksum (if possible)
                try : 
                    assert hash ( fuzzed_file_path ) != file_hash
                
                except : 
                    raw_input ( "DEBUG Hash Fail!" )
                
                
                # parameters contains all the operations
                # we will use to test each file
                parameters = [ " l ", # list
                               #" t ", # test
                               #" h ", # hash
                               #" a ", # add
                               #" x ", # extract
                               #" d ", # delete
                ]
                
                # put the file through its paces.
                for params in parameters :
                    
                    sys_call = params + fuzzed_file_name
                    
                    try : subprocess.check_call ( app + sys_call )
                    
                    
                    ## Test oracle
                    except subprocess.CalledProcessError as exception :
                        print ( "Graceful failure!" )
                        
                        ret_val = exception.returncode
                        cmd_call = exception.cmd
                        print ( "Return value = '{0}' for command '{1}'"
                                .format(ret_val, cmd_call) )
                        
                        # TODO : if failure was due to 'hash failed' (very likely)
                        # correct the checksum and re-run
                    
                    except:
                        raw_input ( "Test Failed! System call = {}"
                                    .format(sys_call) )
                        print ( sys.exc_info()[0] )
                        failure_list.append ( (fuzzed_file_name, sys_call) )
                    
                    else : # success (?!)
                        print ( "Test Passed!  Return value = {}"
                                .format(ret_val) )
                        success_list.append( (fuzzed_file_name, sys_call, ret_val) )
                
                
                # TODO: only delete if ALL tests pass!
                os.remove ( fuzzed_file_path )
            
        
        # TODO: something with failure_list and/or success_list
        print ( "</fuzz_seed> # Done fuzzing using {} as a seed.\n"
                .format(file) )
        
    
    print ( "</test>\n" )
    print ( "Done fuzzing program {}.  Good Job.\n".format(file) )
    print ( "---------------------------------------------------------\n\n" )

random.seed()

test ( app_absolute, file_list )
