
use Test::LectroTest playback_failures => "regression_suite_for_my_module.txt",record_failures   => "failures_in_the_field.txt", trials => 10_000;
use FindBin;               # locate this script
use lib "$FindBin::Bin/";  # use this directory

use verifiers;


# PHONE NUMBERS GENERATORS
my $megaPhoneNumberGen = String( charset=>"0-9", length=>[10,] );
my $miniPhoneNumberGen = String( charset=>"0-9", length=>[1,8] );
my $phoneNumberGen = String( charset=>"0-9", length=>9 );

# PIN GENERATORS
my $megaPinGen = String( charset=>"0-9", length=>[9,] );
my $miniPinGen = String( charset=>"0-9", length=>[0,3] );
my $pinGen = String( charset=>"0-9", length=>[4,8] );

# FILE NAMES GENERATORS
my $fileGen = String( charset=>"a-zA-Z\.\/\-\%=\&\+\*\(\)\{\}\[\]\d\h\?\'<>áàãâäéèêëíìïóòôõöùúûüçñÁÀÃÂÄÉÈÊËÍÌÎÏÓÒÕÔÖÚÙÛÜCÑ", length=>[1,] );
my $extensionGen = Frequency( [8.167,Unit(".txt")], [12.702,Unit(".docx")],[6.996,Unit(".pl")], [ 7.507,Unit(".py")],[2.758,Unit(".tex")] );

# DATATIME GENERATORS
	#YEAR
my $maxYearGen = Int(range=>[2022,9999], sized=>0);
my $minYearGen = Int( range=>[1000,2019], sized=>0 );
my $yearGen = Int( range=>[2020,2021], sized=>0 );
	#MONTH
my $megaMonthGen = Int(range=>[13,99], sized=>0);
my $miniMonthGen = Int(range=>[-99,0]);
my $monthGen = Int(range=>[1,12], sized=>0);
	#DAY
my $megaDayGen = Int(range=>[32,1000], sized=>0);
my $miniDayGen = Int(range=>[-1000,0]);
my $dayGen = Int(range=>[1,28], sized=>0);
	#HOUR
my $megaHourGen = Int(range=>[24,1000], sized=>0);
my $miniHourGen = Int(range=>[-1000,-1], sized=>0);
my $hourGen = Int(range=>[0,23]);
	#MINUTE
my $megaMinuteGen = Int(range=>[64,1000], sized=>0);
my $miniMinuteGen = Int(range=>[-1000,-1], sized=>0);
my $minuteGen = Int(range=>[0,63]);
	#SECOND
my $megaSecondGen = Int(range=>[64,1000], sized=>0);
my $miniSecondGen = Int(range=>[-1000,-1], sized=>0);
my $secondGen = Int(range=>[0,63]);
	# PICKERS
my $yearPicker = Int(range=>[7,8], sized=>0);
my $monthPicker = Int(range=>[9,10], sized=>0);
my $dayPicker = Int(range=>[11,12], sized=>0);
my $hourPicker = Int(range=>[13,14], sized=>0);
my $minutePicker = Int(range=>[15,16], sized=>0);
my $secondPicker = Int(range=>[17,18], sized=>0);

# OTP GENERATORS

my $maxOTPGen = Int(range=>[1000000,999999999], sized=>0 );
my $minOTPGen = Int( range=>[0,99999], sized=>0 );
my $otpGen = Int( range=>[100000,999999], sized=>0 );
my $charOTPGen = String( charset=>"a-zA-Z\.\/\-\%=\&\+\*\(\)\{\}\[\]\d\h\?\'<>áàãâäéèêëíìïóòôõöùúûüçñÁÀÃÂÄÉÈÊËÍÌÎÏÓÒÕÔÖÚÙÛÜCÑ", length=>[1,] );

# PROCESSID GENERATORS 

my $maxProcessIDGen1 = String( charset=>"a-z0-9", length=>[9,] );
my $minProcessIDGen1 = String( charset=>"a-z0-9", length=>[1,7] );
my $processIDGen1 = String( charset=>"a-z0-9", length=>[8] );
my $wrongProcessIDGen1 = String( charset=>"[&%\$#€@\"]!?',;.:-_ªº~^\\|", length=>[8] );
my $maxProcessIDGen2 = String( charset=>"a-z0-9", length=>[5,] );
my $minProcessIDGen2 = String( charset=>"a-z0-9", length=>[1,3] );
my $processIDGen2 = String( charset=>"a-z0-9", length=>[4] );
my $wrongProcessIDGen2 = String( charset=>"[&%\$#€@\"]!?',;.:-_ªº~^\\|", length=>[4] );
my $maxProcessIDGen3 = String( charset=>"a-z0-9", length=>[13,] );
my $minProcessIDGen3 = String( charset=>"a-z0-9", length=>[1,11] );
my $processIDGen3 = String( charset=>"a-z0-9", length=>[12] );
my $wrongProcessIDGen3 = String( charset=>"[&%\$#€@\"]!?',;.:-_ªº~^\\|", length=>[12] );
my $gen1Picker = Int(range=>[2,3], sized=>0);
my $gen2Picker = Int(range=>[4,6], sized=>0);
my $gen3Picker = Int(range=>[7,9], sized=>0);

# RESPONSE GENERATORS

my $responseGen = String( charset=>"A-Za-z0-9+/", length=>[560]);
my $maxResponseGen = String( charset=>"A-Za-z0-9+/", length=>[561,]);
my $minResponseGen = String( charset=>"A-Za-z0-9+/", length=>[1,559]);
my $wrongResponseGen = String( charset=>"[&%\$#€@\"]!?',;.:-_ªº~^\\|", length=>[560]);

# SIGNATURE GENERATORS

my $signatureGen = String( charset=>"A-Za-z0-9+/", length=>[512]);
my $maxSignatureGen = String( charset=>"A-Za-z0-9+/", length=>[513,]);
my $minSignatureGen = String( charset=>"A-Za-z0-9+/", length=>[1,511]);
my $wrongSignatureGen = String( charset=>"[&%\$#€@\"]!?',;.:-_ªº~^\\|", length=>[512]);





Property {
    ##[ 
    	x1 <- $phoneNumberGen, 
    	x2 <- $miniPhoneNumberGen, 
    	x3 <- $megaPhoneNumberGen
    # ]##
    verifiers::valid_number("+351 " . $x1) == 1;
    verifiers::valid_number("+351 " . $x2) == 0;
    verifiers::valid_number("+351 " . $x3) == 0;

}, name => "valid_number's output is 1 for any number given in the range 900000000 and 999999999 and 0 for any others.\n";

Property {
    ##[ 
    	x1 <- $pinGen, 
    	x2 <- $miniPinGen, 
    	x3 <- $megaPinGen
    # ]##
    verifiers::valid_pin($x1) == 1;
    verifiers::valid_pin($x2) == 0;
    verifiers::valid_pin($x3) == 0;

}, name => "valid_pin's output is 1 for any pin given with lengths between 4 and 8 and 0 for any others lengths.\n";


Property {
    ##[ 
    	x1 <- $fileGen,
    	x2 <- $fileGen,
    	x3 <- $fileGen,
    	x4 <- $extensionGen
    # ]##
    verifiers::valid_file( $x1 . '.pdf') == 1;
    verifiers::valid_file( $x3 . x4 ) == 0;
    verifiers::valid_file( $x2 . '.pdf | ' . $x3) == 0;

}, name => "valid_file's output is 1 for any pdf given and 0 for any other type of file or atempt of pipeline.\n" ;


Property {
    ##[ 
    	x1  <- $yearGen,
    	x2  <- $monthGen,
    	x3  <- $dayGen,
    	x4  <- $hourGen,
    	x5  <- $minuteGen,
    	x6  <- $secondGen,
    	x7  <- $maxYearGen,
    	x8  <- $minYearGen,
    	x9  <- $megaMonthGen,
    	x10 <- $miniMonthGen,
    	x11 <- $megaDayGen,
    	x12 <- $miniDayGen,
    	x13 <- $megaHourGen,
    	x14 <- $miniHourGen,
    	x15 <- $megaMinuteGen,
    	x16 <- $miniMinuteGen,
    	x17 <- $megaSecondGen,
    	x18 <- $miniSecondGen,
    	i1  <- $yearPicker,
    	i2  <- $monthPicker,
    	i3  <- $dayPicker,
    	i4  <- $hourPicker,
    	i5  <- $minutePicker,
    	i6  <- $secondPicker,
    # ]##
    verifiers::valid_datatime( "$x1" . "-" . "$x2" . "-" . "$x3T" . "$x4" . ":" . "$x5" . ":" . "$x6.000000" ) == 1;
    verifiers::valid_datatime( "$x($i1)" . "-" . "$x($i2)" . "-" . "$x($i3)T" . "$x($i4)" . ":" . "$x($i5)" . ":" . "$x($i6).000000" ) == 0;

}, name => "valid_datetime's output is 1 for any date given that is from the current year and from the next one and 0 for any other.\n" ;


Property {
    ##[ 
    	x1 <- $otpGen,
    	x2 <- $minOTPGen,
    	x3 <- $maxOTPGen,
    	x4 <- $charOTPGen
    # ]##
    verifiers::valid_otp($x1) == 1;
    verifiers::valid_otp($x2) == 0;
    verifiers::valid_otp($x3) == 0;
    verifiers::valid_otp($x4) == 0;

}, name => "valid_otp's output is 1 for any otp given with lengths between 4 and 8 and 0 for any other lengths.\n" ;


Property {
    ##[ 
    	x1 <- $processIDGen1,
    	x2 <- $maxProcessIDGen1,
    	x3 <- $minProcessIDGen1,
    	x4 <- $processIDGen2,
    	x5 <- $maxProcessIDGen2,
    	x6 <- $minProcessIDGen2,
    	x7 <- $processIDGen3,
    	x8 <- $maxProcessIDGen3,
    	x9 <- $minProcessIDGen3,
    	i1  <- $gen1Picker,
    	i2  <- $gen2Picker,
    	i3  <- $gen3Picker,
    	w1 <- $wrongProcessIDGen1,
    	w2 <- $wrongProcessIDGen2,
    	w3 <- $wrongProcessIDGen3
    	
    # ]##
    verifiers::valid_processId("$x1" . "-" . "$x4" . "-" . "$x4" . "-" . "$x4" . "-" . "$x7") == 1;
    verifiers::valid_processId(undef) == 0;
    verifiers::valid_processId("$x($i1)" . "-" . "$x($i2)" . "-" . "$x($i2)" . "-" . "$x($i2)" . "-" . "$x($i3)") == 0;
    verifiers::valid_processId("$w1" . "-" . "$w2" . "-" . "$w2" . "-" . "$w2" . "-" . "$w3") == 0;

}, name => "valid_processId's output is 1 for any process_id given with the propper values formation (8,4,4,4,12) and right characters(a-z0-9) and 0 for any other formation or diferent characters.\n" ;


Property {
    ##[ 
    	x1 <- $responseGen,
    	x2 <- $minResponseGen,
    	x3 <- $maxResponseGen,
    	x4 <- $wrongResponseGen
    # ]##
    verifiers::valid_response($x1) == 1;
    verifiers::valid_response($x2) == 0;
    verifiers::valid_response($x3) == 0;
    verifiers::valid_response($x4) == -2;
    verifiers::valid_response(undef) == -1;

}, name => "valid_response's output is 1 for any response given with length 560 and only containing Base 64 characters and 0 for any other lengths or characters.\n" ;


Property {
    ##[ 
    	x1 <- $signatureGen,
    	x2 <- $minSignatureGen,
    	x3 <- $maxSignatureGen,
    	x4 <- $wrongSignatureGen
    # ]##
    verifiers::valid_Signature($x1) == 1;
    verifiers::valid_Signature($x2) == 0;
    verifiers::valid_Signature($x3) == 0;
    verifiers::valid_Signature($x4) == -2;
    verifiers::valid_Signature(undef) == -1;

}, name => "valid_Signature's output is 1 for any Signature given with length 512 and only containing Base 64 characters and 0 for any other lengths or characters.\n" ;







