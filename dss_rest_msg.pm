package dss_rest_msg;
=head
Funções que preparam e executam os comandos REST do DSS, nomeadamente:
  + getDataToSign(dataToSignDTO: ns0:dataToSignOneDocumentDTO) 
            -> response: ns0:toBeSignedDTO
  + signDocument(signDocumentDTO: ns0:signOneDocumentDTO) 
            -> response: ns0:remoteDocument
=cut

use Digest::SHA;
use MIME::Base64;
use REST::Client;
# Modulos para debug
#use diagnostics;
use warnings;
use strict;

my $DEBUG = 0;

#FUNCIONA
# Função para ativar o debug, permitindo mostrar mensagens enviadas e recebidas do servidor SOAP
sub debug{
    my @aux = @_;
    $DEBUG = $aux[0];
    print("Debug on!!") unless $DEBUG == 0;
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

=head 
    Prepara e executa o comando DSS getDataToSign.

    Parameters
    ----------
    certs_chain : array de certificados
        Contém certificado de assinatura, EC intermédia e Root.
    signdate : datetime, em formato ISO 
        Data e hora de assinatura em formato ISO.
    pdf: Estrutura com ficheiro e nome do ficheiro
        PDF a assinar e nome do ficheiro de onde foi lido.
    dss_rest: URI
        Servidor DSS Rest - Web Services

    Returns
    -------
    ns0:toBeSignedDTO(bytes: xsd:base64Binary)
        Devolve o DTBS (i.e., Data to be signed) do PDF.
=cut
sub getDataToSign{
    my @aux1 = @_; 
    my $certs = $aux1[0];
    my $signdate = $aux1[1];
    my %pdf = %{$aux1[2]};
    my $dss_rest = $aux1[3];


    my $request_data = '{
        "parameters": {
            "signWithExpiredCertificate": false,
            "generateTBSWithoutCertificate": false,
            "signatureLevel": "PAdES_BASELINE_B",
            "signaturePackaging": "ENVELOPED",
            "encryptionAlgorithm": "RSA",
            "digestAlgorithm": "SHA256",
            "referenceDigestAlgorithm": null,
            "maskGenerationFunction": null,
            "signingCertificate": {
                "encodedCertificate": "' . @$certs[0] . '"
            },
            "certificateChain": [
                {"encodedCertificate": "' . @$certs[1] . '" },
                {"encodedCertificate":"' . @$certs[2] .'" }
            ],
            "detachedContents": null,
            "asicContainerType": null,
            "blevelParams": {
                "trustAnchorBPPolicy": true,
                "signingDate":"' . $signdate . '",
                "claimedSignerRoles": null,
                "commitmentTypeIndications": null
            }
        },
        "toSignDocument": {
            "bytes": "' . encode_base64($pdf{'bytes'}) . '",
            "name": "' . $pdf{'name'} . '"
        }
    }';

    my $request = HTTP::Request->new('POST'=> $dss_rest . '/getDataToSign');
     $request->header('content-type' => 'application/json');
     $request->content($request_data);

    my $ua = LWP::UserAgent->new;
    remove_debug() unless $DEBUG;
    my $response = $ua->request($request);

    if ($response->is_success) {
        return getSignature($response->content);
    } else{
        die"Erro " . $response->status_line . ".\n\n If ur trying to use this aplication the right way bare in mind that u can not use datatimes prior to 1 month and 7 days ago.\n\n";
    }
    return 1;
}

sub getSignature{
    my @aux1_1 = @_;
    my $hash = $aux1_1[0];
    $hash =~ s/[key => {[\n\s]*"bytes"\s*:\s*"//;
    $hash =~ s/"[\n\s]*}//;
    return $hash; 
}

=head 
    Prepara e executa o comando DSS getDataToSign.

    Parameters
    ----------
    certs_chain : array de certificados
        Contém certificado de assinatura, EC intermédia e Root.
    signdate : datetime, em formato ISO 
        Data e hora de assinatura em formato ISO.
    pdf: Estrutura com ficheiro e nome do ficheiro
        PDF a assinar e nome do ficheiro de onde foi lido.
    res: Estrutura com assinatura
        Assinatura do PDF
    dss_rest: URI
        Servidor DSS Rest - Web Services

    Returns
    -------
    ns0:remoteDocument(bytes: xsd:base64Binary, digestAlgorithm: ns0:digestAlgorithm, name: xsd:string)
        Devolve uma estrutura com o PDF assinado (bytes).
=cut
sub signDocument{
    my @aux2 = @_;
    my $certs = $aux2[0];
    my $signdate = $aux2[1];
    my %pdf = %{$aux2[2]};
    my $signature = $aux2[3];
    my $dss_rest = $aux2[4];

    my $request_data = '{
        "parameters": {
            "signWithExpiredCertificate": false,
            "generateTBSWithoutCertificate": false,
            "signatureLevel": "PAdES_BASELINE_B",
            "signaturePackaging": "ENVELOPED",
            "encryptionAlgorithm": "RSA",
            "digestAlgorithm": "SHA256",
            "referenceDigestAlgorithm": null,
            "maskGenerationFunction": null,
            "signingCertificate": {
                "encodedCertificate": "' . @$certs[0] . '"
            },
            "certificateChain": [
                {"encodedCertificate": "' . @$certs[1] . '" },
                {"encodedCertificate":"' . @$certs[2] .'" }
            ],
            "detachedContents": null,
            "asicContainerType": null,
            "blevelParams": {
                "trustAnchorBPPolicy": true,
                "signingDate":"' . $signdate . '",
                "claimedSignerRoles": null,
                "commitmentTypeIndications": null
            }
        },
        "signatureValue": {
            "algorithm": "RSA_SHA256",
            "value": "' . encode_base64($signature) . '"
        },
        "toSignDocument": {
            "bytes": "' . encode_base64($pdf{'bytes'}) . '",
            "name": "' . $pdf{'name'} .'"
        }
    }';


    my $request = HTTP::Request->new('POST'=> $dss_rest . '/signDocument');
    $request->header('content-type' => 'application/json');
    $request->content($request_data);

    my $ua = LWP::UserAgent->new;
    remove_debug() unless $DEBUG;
    my $response = $ua->request($request);
    if ($response->is_success) {
        return getSignedPDF($response->content);
    } else{
        print($response->as_string);
        die"Erro " . $response->status_line . ".\n";
    }
    return 1;
}

sub getSignedPDF{
    my @aux2_1 = @_;
    my $hash = $aux2_1[0];
    $hash =~ s/[{[\n\s]*"bytes"\s*:\s*"//;
    $hash =~ s/",["a-zA-Z:,-\.\n\s]*}//;
    return $hash;
}

1;
