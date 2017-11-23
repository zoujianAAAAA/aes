<?php
	class AES{

		public function decrypt($data,$key){
			$key = $this->hextobin($key);
			return trim($this->pkcs5_unpad(mcrypt_decrypt(MCRYPT_RIJNDAEL_128,$key,$this->hextobin($data),MCRYPT_MODE_ECB,'')));
		}
		
		public	function encrypt($input, $key) {
		    $size = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);
		    $input = $this->pkcs5_pad($input, $size);
		    $td = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_ECB, '');
		    $iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
		    mcrypt_generic_init($td, $this->hextobin($key), $iv);
		    $data = mcrypt_generic($td, $input);
		    mcrypt_generic_deinit($td);
		    mcrypt_module_close($td);
		    $data = bin2hex($data);
		    return $data;
		}

		private function hextobin($hexstr){
			$n = strlen($hexstr);
			$sbin = "";
			$i=0;
			while($i<$n){
				$a = substr($hexstr,$i,2);
				$c = pack("H*",$a);
				if($i==0) $sbin = $c;
				else	  $sbin.=$c;
				$i+=2;
			}
			return $sbin;
		}
		public function pkcs5_pad($text){
			$pad = 16-(strlen($text)%16);
			return $text.Str_repeat(chr($pad),$pad);
		}
		public function pkcs5_unpad($text){
			$pad = ord($text{strlen($text)-1});
			if($pad > strlen($text))  return false;
			if(strspn($text,chr($pad),strlen($text)-$pad) != $pad)  return false;
			return substr($text,0,-1*$pad);
		}
	}
	
	$aes = new AES();
	$key = "bede181859ac72c748018b15224bb0d3";
	$data = "ip=18.1.1.217&cid=51688786-4a5d-4bf2-ba09-3d5c935af7044fe40860-197a-4b66-abc4-25d7f561fad2&ncid=28be0978-392a-4093-a5c7-9f12b94b7d5e&random=4990c74a-6b20-4502-b5bb-5ea6e3cc482e&signature=fcd233b0-3aeb-4f2c-b947-f1eccdaef3b3";
	$data_ECB = $aes->encrypt($data,$key);
	echo $data_ECB."---------------\n";
	//$data = "b5deeff3f75b1f8743749bc8742c900635c3c06984e1fd5a34b83a700a7796fc";
	//$data_ECB = "fda59e0b619063ecdc8c11304ee8e05d882f2d5e565e0d2551fbec5bf405e3119209739df9aae92bd8ee1d653a15e2fd5afff9662e859acc5869011a2ab368b11e5417758847f661ecde929cb96ba66617713b92fe44aa69771f609774247798b6a5939ace2059ebe72e27589ec0f34502315df0008fd8d0836837df4258a16edf48e7e769c1f0aa1178e1e66cbc4ef79efb51677012fd063c9a98c22d6afec8e33c01093ec12e807857b22a47c41d7dacfbc9a399346708d6d376012ffb88642c59ab9f1762da8e51156be3daff952ce62781e434dbc4780a90727cbba6c0a9";
	echo "decrypt:".$aes->decrypt($data_ECB,$key);
	
?>
