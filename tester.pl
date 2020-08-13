use Test::Vars;
use FindBin;               # locate this script
use lib "$FindBin::Bin/";  # use this directory


vars_ok('signpdf_config.pm');
vars_ok('cmd_soap_msg.pm');
vars_ok('dss_rest_msg.pm');
vars_ok('verifiers.pm');
1;