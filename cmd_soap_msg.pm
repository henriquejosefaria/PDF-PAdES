package cmd_soap_msg;
=head
Funções que preparam e executam os comandos SOAP do SCMD, nomeadamente:
  + GetCertificate
          (applicationId: xsd:base64Binary, userId: xsd:string)
          -> GetCertificateResult: xsd:string
  + CCMovelSign
        (request: ns2:SignRequest)
        -> CCMovelSignResult: ns2:SignStatus
  + CCMovelMultipleSign
        (request: ns2:MultipleSignRequest, documents: ns2:ArrayOfHashStructure)
        -> CCMovelMultipleSignResult: ns2:SignStatus
  + ValidateOtp
        (code: xsd:string, processId: xsd:string,
            applicationId: xsd:base64Binary)
        -> ValidateOtpResult: ns2:SignResponse
=cut

# preparation
use XML::Compile::WSDL11;      # use WSDL version 1.1
use XML::Compile::SOAP11;      # use SOAP version 1.1
use XML::Compile::Transport::SOAPHTTP;
use MIME::Base64;
use Encode;             # para encode e decode
use Bit::Vector;
use Digest::SHA qw(sha256);
use XML::Parser;
use HTTP::Request;
use HTTP::Parser;
use MIME::Base64;
use LWP::ConsoleLogger::Everywhere ();
use List::MoreUtils ':like_0.33';
use Carp;
use warnings;
use strict;

my $DEBUG = 0;
$|++;

#FUNCIONA
# Função para ativar o debug, permitindo mostrar mensagens enviadas e recebidas do servidor SOAP
sub debug{
    my @aux = @_;
    $DEBUG = $aux[0];
    print(">> Debug: On\n\n") unless $DEBUG == 0;
    return 1;
}

sub remove_debug{
    my $loggers = LWP::ConsoleLogger::Everywhere->loggers;
    foreach my $logger ( @{ $loggers } ) {
        # stop dumping headers
        $logger->dump_content(0);
        $logger->dump_headers(0);
        $logger->dump_params(0);
        $logger->dump_status(0);
        $logger->dump_text(0);
        $logger->dump_title(0);
        $logger->dump_text(0);
        $logger->dump_uri(0);
        $logger->pretty(0);
    }
    return 1;
}

#FUNCIONA
# Função que devolve o URL do WSDL do SCMD (preprod ou prod)
sub get_wsdl{
    my @helper = @_;
    my @wsdl = ('https://preprod.cmd.autenticacao.gov.pt/Ama.Authentication.Frontend/CCMovelDigitalSignature.svc?wsdl',
            'https://cmd.autenticacao.gov.pt/Ama.Authentication.Frontend/CCMovelDigitalSignature.svc?wsdl');


    my ($input) = $helper[0];

    # não há necessidade de testar o prod por este ser 0 ou 1 sempre 
    # garantido pelo Getopt ao fazer o parsing do @ARGV

    my $choice = int($input);
 

    return $wsdl[$choice];
}

#FUNCIONA
sub hashPrefix{
    my @helper = @_;
    #obter o hashtype e a hash dos argumentos passados
    my ($hashtype,$hash)  = @helper;

    croak "Only SHA256 available" unless $hashtype eq "SHA256";

    my @array_strings = ("0x30", "0x31", "0x30", "0x0d", "0x06", "0x09", "0x60", "0x86", "0x48", "0x01", "0x65", "0x03", "0x04", "0x02", "0x01", "0x05", "0x00", "0x04", "0x20");

    my @array_binarios = map {sprintf("%b", hex($_))} @array_strings;

    my $ final_byte_string = join '', @array_binarios;

    #Criação de um dicionário para teste
    my %prefix = ("SHA256" => $final_byte_string);

    return $prefix{"SHA256"} . $hash;
}

#FUNCIONA
sub response_parser_certificate{
    my @aux0 = @_;
    my $str = $aux0[0];
    my @mycerts = split /<\/?GetCertificateResult>/, $str;
    my $certs = $mycerts[1];
    
    my @temporary_certs = split /-----BEGIN CERTIFICATE-----/, $certs;
    my @pre_aux = map {split /-----END CERTIFICATE-----/ ,$_} @temporary_certs;

    my $length = @pre_aux;
    if($length < 3){
        croak "Wrong number of Certificate";
    }
    
    map{MIME::Base64::decode($_);} @pre_aux; # meramente por precaução -> não é preciso
    
    for ( @pre_aux ) {
        $_ = '-----BEGIN CERTIFICATE-----'. $_ .'-----END CERTIFICATE-----' ;
    }
    my @aux = undef;
    for (@aux = @pre_aux) { $_ =~ s/&#xD;/ /g };

    my @certificates;
    $certificates[0] = $aux[0];
    $certificates[1] = $aux[2];
    $certificates[2] = $aux[4];

    return @certificates;

}

#FUNCIONA
sub getcertificate{
    my @aux1 = @_;

    my $SOAP_ACTION = "http://Ama.Authentication.Service/CCMovelSignature/GetCertificate";
    my $stringUrl = "https://cmd.autenticacao.gov.pt/Ama.Authentication.Frontend/CCMovelDigitalSignature.svc";

    # Só aceitamos nesta função 2 argumentos
    my $number_of_args = scalar(@aux1);
    croak "Insuficient args" unless $number_of_args == 2;

    #obter a applicationId e o userId dos argumentos passados
    my $appId  = $aux1[1][9];
    my $userId = $aux1[1][1];

    #Criação de um dicionário
    my $encodedAppId = encode_base64(encode('UTF-8',$appId));
    my $body = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">" .
                    "<soapenv:Header/>" .
                    "<soapenv:Body>" .
                    "<GetCertificate xmlns=\"http://Ama.Authentication.Service/\">" .
                    "<applicationId>" . $encodedAppId . "</applicationId>" .
                    "<userId>" . $userId . "</userId>" .
                    "</GetCertificate>" .
                    "</soapenv:Body>" .
                    "</soapenv:Envelope>";

    ########################################################
    my $request = HTTP::Request->new('POST'=> $stringUrl
        ,[
            'Accept-Encoding' => 'UTF-8'
            ,'Content-Type' =>'text/xml;charset=utf-8'
            ,SOAPAction => $SOAP_ACTION
        ]
        ,$body);

    my $ua = LWP::UserAgent->new;
    remove_debug() unless $DEBUG;
    my $response = $ua->request($request);
    my @certificates = undef;
    if ($response->is_success) {
        @certificates = response_parser_certificate($response->content);
    } else{
        die "Erro " . $response->status_line . ". Impossível obter certificado.\n";
    }
    return @certificates;
}

#FUNCIONA
sub response_parser_signature{
    my @aux2_1 = @_;
    my $str = $aux2_1[0];
    my @mySignature = split /<\/?a:ProcessId>/, $str;
    return $mySignature[1];
}

#FUNCIONA
sub ccmovelsign{
    my @aux2 = @_;
    my $SOAP_ACTION = "http://Ama.Authentication.Service/CCMovelSignature/CCMovelSign";
    my $stringUrl = "https://cmd.autenticacao.gov.pt/Ama.Authentication.Frontend/CCMovelDigitalSignature.svc";

    # Obter o tipo de hash a usar
    my $hashtype;
    if(! defined($aux2[2])){
        $hashtype = "SHA256";
    } else{
        $hashtype = $aux2[2];
    }
    # Obtenção do ficheiro
    if(! defined $aux2[1][3]){
        $aux2[1][3] = 'docname teste';
    }
    # Obtenção do hash 
    my $hash = $aux2[1][10];
    if(! defined $aux2[1][10]){
        my$message = sprintf("%b",'Nobody inspects the spammish repetition');
        $hash = sha256($message);
    }
    $hash = encode_base64(encode('UTF-8',hashPrefix($hashtype, $hash)));

    my $appId = $aux2[1][9];
    my $docName = $aux2[1][3];
    my $pin = $aux2[1][2];
    my $userId = $aux2[1][1];

    my $encodedAppId = encode_base64(encode('UTF-8',$appId));

    my $body = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">" .
                    "<soapenv:Body>" .
                    "<CCMovelSign xmlns=\"http://Ama.Authentication.Service/\">" .
                    "<request xmlns:a=\"http://schemas.datacontract.org/2004/07/Ama.Structures.CCMovelSignature\" xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\">" .
                    "<a:ApplicationId>" . $encodedAppId . "</a:ApplicationId>" .
                    "<a:DocName>" . $docName . "</a:DocName>" .
                    "<a:Hash>" . $hash . "</a:Hash>" .
                    "<a:Pin>" . $pin . "</a:Pin>" .
                    "<a:UserId>" . $userId . "</a:UserId>" .
                    "</request>" .
                    "</CCMovelSign>" .
                    "</soapenv:Body>" .
                    "</soapenv:Envelope>";

    ########################################################
    my $request = HTTP::Request->new('POST'=> $stringUrl
        ,[
            'Accept-Encoding' => 'UTF-8'
            ,'Content-Type' =>'text/xml;charset=utf-8'
            ,SOAPAction => $SOAP_ACTION
        ]
        ,$body);

    my $ua = LWP::UserAgent->new;
    remove_debug() unless $DEBUG;
    my $response = $ua->request($request);
    my $processId = undef;
    if ($response->is_success) {
        $processId = response_parser_signature($response->content);
    } else{
        die"Erro " . $response->status_line . ". Valide o PIN introduzido.\n";
    }
    return $processId;

}

#FUNCIONA
sub ccmovelmultiplesign{
    my @aux3 = @_; 
    my $SOAP_ACTION = "http://Ama.Authentication.Service/CCMovelSignature/CCMovelMultipleSign";
    my $stringUrl = "https://cmd.autenticacao.gov.pt/Ama.Authentication.Frontend/CCMovelDigitalSignature.svc";

    # Obter o tipo de hash a usar
    my $hashtype;
    if(! defined($aux3[2])){
        $hashtype = "SHA256";
    } else{
        $hashtype = $aux3[2];
    }
    # Obtenção do ficheiro
    if(! defined $aux3[1][3]){
        $aux3[1][3] = 'docname teste';
    }
    # Obtenção do hash
    my $hash = $aux3[1][10];
    if(! defined $aux3[1][10]){
        my$message = sprintf("%b",'Nobody inspects the spammish repetition');
        $hash = sha256($message);
    }
    $hash = encode_base64(encode('UTF-8',hashPrefix($hashtype, $hash)));

    my $appId = $aux3[1][9];
    my $docName = $aux3[1][3];
    my $pin = $aux3[1][2];
    my $userId = $aux3[1][1];

    my $encodedAppId = encode_base64(encode('UTF-8',$appId));

    my $id1 = '1234';
    my $id2 = '1235';
    my $body = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">" .
                    "<soapenv:Body>" .
                    "<CCMovelMultipleSign xmlns=\"http://Ama.Authentication.Service/\">" .
                    "<request xmlns:a=\"http://schemas.datacontract.org/2004/07/Ama.Structures.CCMovelSignature\" xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\">" .

                    "<a:ApplicationId>" . $encodedAppId . "</a:ApplicationId>" .
                    "<a:Pin>" . $pin . "</a:Pin>" .
                    "<a:UserId>" . $userId . "</a:UserId>" .

                    "<documents>" .

                    "<a:Hash>" . $hash . "</a:Hash>" .
                    "<a:DocName>" . $docName . "</a:DocName>" .
                    "<a:id>" . $id1 . "</a:id>" .

                    "<a:Hash>" . $hash . "</a:Hash>" .
                    "<a:DocName>" . $docName . "</a:DocName>" .
                    "<a:id>" . $id2 . "</a:id>" .

                    "</documents>" .
                    "</request>" .
                    "</CCMovelMultipleSign>" .
                    "</soapenv:Body>" .
                    "</soapenv:Envelope>";

    my $request = HTTP::Request->new('POST'=> $stringUrl
        ,[
            'Accept-Encoding' => 'UTF-8'
            ,'Content-Type' =>'text/xml;charset=utf-8'
            ,SOAPAction => $SOAP_ACTION
        ]
        ,$body);

    my $ua = LWP::UserAgent->new;
    remove_debug() unless $DEBUG;
    my $response = $ua->request($request);
    my $processId = undef;
    if ($response->is_success) {
        $processId = response_parser_signature($response->content);
    } else{
        die"Erro " . $response->status_line . ". Valide o PIN introduzido.\n";
    }
    return $processId;

}

#FUNCIONA
sub response_parser_otp{
    my @aux4_1 = @_;
    my $str = $aux4_1[0];
    my @mySignature = split /<\/?a:Signature>/, $str;
    return $mySignature[1];
}

#FUNCIONA
sub validate_otp{
    my @aux4 = @_;
    my $SOAP_ACTION = "http://Ama.Authentication.Service/CCMovelSignature/ValidateOtp";
    my $stringUrl = "https://cmd.autenticacao.gov.pt/Ama.Authentication.Frontend/CCMovelDigitalSignature.svc";

    my $appId = $aux4[1][9];
    my $processId = $aux4[1][11];
    my $otp = $aux4[1][4];

    my $encodedAppId = encode_base64(encode('UTF-8',$appId));


    my $body = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">" .
                    "<soapenv:Header/>" .
                    "<soapenv:Body>" .
                    "<ValidateOtp xmlns=\"http://Ama.Authentication.Service/\">" .
                    "<code>" . $otp . "</code>" .
                    "<processId>" . $processId . "</processId>" .
                    "<applicationId>" . $encodedAppId . "</applicationId>" .
                    "</ValidateOtp>" .
                    "</soapenv:Body>" .
                    "</soapenv:Envelope>";

    my $request = HTTP::Request->new('POST'=> $stringUrl
        ,[
            'Accept-Encoding' => 'UTF-8'
            ,'Content-Type' =>'text/xml;charset=utf-8'
            ,SOAPAction => $SOAP_ACTION
        ]
        ,$body);

    my $ua = LWP::UserAgent->new;
    remove_debug() unless $DEBUG;
    my $response = $ua->request($request);
    my $signature = undef;
    if ($response->is_success) {
        $signature = response_parser_otp($response->content);
    } else{
        die "Erro " . $response->status_line . ". Impossível obter certificado.\n";
    }
    return $signature;
}


# este parâmetro tem de existir por sintaxe do perl
1;