package verifiers;

use Perl::Tidy;
use warnings;
use strict;


sub sqlInjection{
	my @aux = @_;
	my $argument = $aux[0];
	return 0 if(! defined $argument);
	#print("SEARCHING FOR SQL INJECTIONS ON $argument\n");
	my @array_sql_expressions = ('SELECT ',' \* ',' FROM ','DELETE ','CREATE ','TRANSACTION ','BEGIN ','USING ','ON ','AND ','NOT ','MATCHED ','THEN ','UPDATE ','MERGE ','INTO ','SET ','INSERT ','WHERE ','\"','DROP ',' END');
	map {return 1 if ($argument =~ /$_/i);} @array_sql_expressions;
	return 0;
}

sub xmlInjection{
	my @aux1 = @_;
	my $argument = $aux1[0];
	return 0 if(! defined $argument);
	#print("SEARCHING FOR XML INJECTIONS ON $argument\n");
	# Se o input tiver este padrão <qualquer coisa> ... </qualquer coisa> asssumimos ser xml!!
    return 1 if ($argument =~ /<[a-zA-Z]*(>[^(<\/)]*<\/[a-zA-Z]*|\/)?>/);
    return 0;
}

#[1]  -f      -> ficheiro (verificar tamanho & não tem | para fazer pipeline)
#[2]  -u      -> número de utilizador (apenas números - indicativo espaço e 9 digitos)
#[3]  -p      -> pin (número de tamanho 4)
#[4]  -otp    -> input line code received on selfphone (VAZIO/apenas digitos)
#[5]  -procId -> Process Id (VAZIO/numeros)
#[7]  -prod   -> escolher prepod ou pod {0,1}

sub input{
	my @aux2 = @_;
	my @args = @{$aux2[0]};
	
	if(defined $args[1]){
		#print("a testar phone number!\n");
		#Verificação de números internacionais com indicativo do pais e número
		#die "Wrong Phone Number!! The notation is: +XXX NNNNNNNNN\n" unless $args[2] =~ /^\+[0-9]{1,3} [0-9]{4,14}$/;	
		#Verificação de números nacionais com indicativo do pais e número
		die "Wrong Phone Number!! The notation is: +XXX NNNNNNNNN\n" unless $args[1] =~ /^\+351 [0-9]{9}$/;	
	
	}
	if(defined $args[2]){
		#print("a testar pin!\n");
		#Verificação do pin
		die "Wrong Pin!! The notation is a 4-8 number sequence\n" unless $args[2] =~ /^[0-9]{4,8}$/;		
	}
	if(defined $args[3]){
		#Verificação da correção do nome/caminho do ficheiro alvo -> serve para impedir pipelining e ficheiros com nomes errados
		# WHITE LIST
		die "(White List) Do not try to pipeline or use any strange character on the file to be read...\n" unless $args[3] =~ /^[a-zA-Z\.\/\-\%=\&\+\*\(\)\{\}\[\]0-9\?\'<>áàãâäéèêëíìïóòôõöùúûüçñÁÀÃÂÄÉÈÊËÍÌÎÏÓÒÕÔÖÚÙÛÜCÑ ]+\.pdf$/;
		# BLACK LIST -> sere para o caso em que não se fornece argumento e a string é o nome da opção seguinte
		die "(Black List) Do not try to pipeline or use any strange character on the file to be read...\n" unless $args[3] !~ /^(-)?[(u)(p)(otp)(procId)(app)(prod)(d)]{1}$/;
		#die "(Black List) Do not try to pipeline or use any strange character on the file to be read..." unless $args[1] !~ /[\|;,'?!"\\]/;	
	}
	if(defined $args[5]){
		#Verificação da correção do nome/caminho do ficheiro alvo -> serve para impedir pipelining e ficheiros com nomes errados
		# WHITE LIST
		die "(White List) Do not try to pipeline or use any strange character on the file to be read...\n" unless $args[5] =~ /^[a-zA-Z\.\/\-\%\&\+\*\(\)\{\}\[\]0-9\?\'<>áàãâäéèêëíìïóòôõöùúûüçñÁÀÃÂÄÉÈÊËÍÌÎÏÓÒÕÔÖÚÙÛÜCÑ ]+\.pdf$/;
		# BLACK LIST -> sere para o caso em que não se fornece argumento e a string é o nome da opção seguinte
		die "(Black List) Do not try to pipeline or use any strange character on the file to be read...\n" unless $args[5] !~ /^(-)?[(u)(p)(infile)(outfile)(datetime)]{1}$/;
		#die "(Black List) Do not try to pipeline or use any strange character on the file to be read..." unless $args[1] !~ /[\|;,'?!"\\]/;	
	}
	if(defined $args[6]){
		die "Input data must have the specified format: YYYY-MM-DDThh:mm:ss.mmmmmm\n" unless $args[6] =~ /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{6}$/;
	}
	return 1;
}

sub valid_otp{
	my @aux3 = @_;
	my $argument = $aux3[0];
	if(defined($argument)){
		die "Wrong OTP!! The notation is: XXXXXX\n" unless $argument =~ /^[0-9]{6}$/;
	}
	else{
		die "OTP not defined!\n"
	}
	return 1;
}

sub valid_processId{
	my @aux4 = @_;
	my $argument = $aux4[0];

	if(defined($argument)){
		die "Wrong ProcessId!! The notation is: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX.\n" unless $argument =~ /^[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}$/;
	}
	else{
		die "ProcessId not defined!\n"
	}
	return 1;
}

sub valid_response{
	my @aux5 = @_;
	my $argument = $aux5[0];

	if(defined($argument)){
		# verifica o tamanho do input recebido
		die "Illegal length found on Response!!\n" unless length($argument) == 560;
		# verifica a validade de todos os caracteres
		die "Wrong Response!!\n" unless $argument =~ /^[a-zA-Z0-9+\/]+$/;
	}
	else{
		die "Response not defined!\n"
	}
	return 1;
}

sub valid_Signature{
	my @aux6 = @_;
	my $argument = $aux6[0];

	if(defined($argument)){
		# verifica o tamanho do input recebido
		die "Illegal length found on Signature!!\n" unless length($argument) == 512;
		# verifica a validade de todos os caracteres
		die "Wrong Signature!!\n" unless $argument =~ /^[a-zA-Z0-9+\/]+$/;
	}
	else{
		die "Response not defined!\n"
	}
	return 1;
}

1;