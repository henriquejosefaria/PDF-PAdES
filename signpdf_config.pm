package signpdf_config;
#Ficheiro de configuração.
use warnings;
use strict;

# ApplicationId da entidade, fornecida pela AMA
#
my $APPLICATION_ID = 'b826359c-06f8-425e-8ec3-50a97a418916';

# Servidor WebApp DSS - REST services

my $DSS_REST = 'https://dss.devisefutures.com/services/rest/signature/one-document';


############## NÃO ALTERAR A PARTIR DAQUI ####################


sub get_appid{
=head
    Devolve APPLICATION_ID (fornecida pela AMA).

    Returns
    -------
    string
        APPLICATION_ID da entidade, fornecida pela AMA.

    """
=cut
    return $APPLICATION_ID;
}

# Função que devolve o URL topo dos webservice do DSS
sub get_rest{
=head
    """Devolve URL do servidor dos webservice do DSS.

    Returns
    -------
    string
        URL dos Webservices do DSS.

    """
=cut
    return $DSS_REST;
}

1;