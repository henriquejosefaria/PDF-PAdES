package verifiers;

use Perl::Tidy;
use DateTime;
use Date::Manip::Range;
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
	my @aux = @_;
	my @args = @{$aux[0]};
	if(defined $args[1]){	
		#Verificação de números nacionais com indicativo do pais e número
		die "Wrong Phone Number!! The notation is: +XXX NNNNNNNNN\n" unless valid_number($args[1]);
	}
	if(defined $args[2]){
		#Verificação do pin
		die "Wrong Pin!! The notation is a 4-8 number sequence\n" unless valid_pin($args[2]);
	}
	if(defined $args[3]){
		#Verificação da correção do nome/caminho do ficheiro alvo -> serve para impedir pipelining e ficheiros com nomes errados
		die "Do not try to pipeline or use any strange character on the file to be read...\n" unless valid_file($args[3]);
	}
	if(defined $args[5]){
		#Verificação da correção do nome/caminho do ficheiro alvo -> serve para impedir pipelining e ficheiros com nomes errados
		die "Do not try to pipeline or use any strange character on the file to be read...\n" unless valid_file($args[5]);
	}
	if(defined $args[6]){
		die "Input data must have the specified format: YYYY-MM-DDThh:mm:ss.mmmmmm\n" unless valid_datatime($args[6]);
	}
	return 1;
}

sub valid_number{
	my @aux = @_;
	my $number = $aux[0];
	#Verificação de números nacionais com indicativo do pais e número
	return 0 unless $number =~ /^\+351 [0-9]{9}$/;	
	return 1;
}

sub valid_pin{
	my @aux0 = @_;
	my $pin = $aux0[0];
	#Verificação do pin
	return 0 unless $pin =~ /^[0-9]{4,8}$/;	
	return 1;	
}

sub valid_file{
	my @aux1 = @_;
	my $file = $aux1[0];
	#Verificação da correção do nome/caminho do ficheiro alvo -> serve para impedir pipelining e ficheiros com nomes errados
	# WHITE LIST
	return 0 unless $file =~ /^[a-zA-Z\.\/\-\%=\&\+\*\(\)\{\}\[\]\d\h\?\'<>áàãâäéèêëíìïóòôõöùúûüçñÁÀÃÂÄÉÈÊËÍÌÎÏÓÒÕÔÖÚÙÛÜCÑ]+\.pdf$/;
	# BLACK LIST -> sere para o caso em que não se fornece argumento e a string é o nome da opção seguinte
	return 0 unless $file !~ /^(-)?[(u)(p)(otp)(procId)(app)(prod)(d)(\n)(outfile)(datetime)]{1}$/;
	return 0 unless sqlInjection($file) == 0;
	return 0 unless xmlInjection($file) == 0;
	return 1;
}

sub valid_datatime{
	my @aux2 = @_;
	my $datatime = $aux2[0];
	return 0 unless $datatime =~ /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{6}$/;

	my $currentYear = int(DateTime->now()->strftime( '%Y'));
	my $year = int(substr $datatime , 0, 4);
	my $month = int(substr $datatime , 5, 2);
	my $day = int(substr $datatime , 8, 2);
	my $hour = int(substr $datatime , 11, 2);
	my $minute = int(substr $datatime , 14, 2);
	my $second = int(substr $datatime , 17, 2);

	if ($year < $currentYear or $year > $currentYear+1 or $month < 1 or $month > 12 or $day < 1 or $day > 31 or $hour < 0 or $hour > 23 or $minute < 0 or $minute > 63 or $second < 0 or $second > 63){
		return 0;
	}
	my $range = Date::Manip::Range->new(parse => $datatime);
	return 0 unless $range-> is_valid();

	return 1;
}

sub valid_otp{
	my @aux3 = @_;
	my $argument = $aux3[0];
	if(defined($argument)){
		return 0 unless $argument =~ /^[0-9]{6}$/;
	}
	else{
		return -1;
	}
	return 1;
}

sub valid_processId{
	my @aux4 = @_;
	my $argument = $aux4[0];

	if(defined($argument)){
		return 0 unless $argument =~ /^[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}$/;
	}
	else{
		return -1;
	}
	return 1;
}

sub valid_response{
	my @aux5 = @_;
	my $argument = $aux5[0];

	if(defined($argument)){
		# verifica o tamanho do input recebido
		return 0 unless length($argument) == 560;
		# verifica a validade de todos os caracteres
		return -2 unless $argument =~ /^[a-zA-Z0-9+\/]+$/;
	}
	else{
		return -1;
	}
	return 1;
}

sub valid_Signature{
	my @aux6 = @_;
	my $argument = $aux6[0];

	if(defined($argument)){
		# verifica o tamanho do input recebido
		return 0 unless length($argument) == 512;
		# verifica a validade de todos os caracteres
		return -2 unless $argument =~ /^[a-zA-Z0-9+\/]+$/;
	}
	else{
		return -1;
	}
	return 1;
}

1;