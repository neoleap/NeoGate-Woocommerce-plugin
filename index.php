<?php
/*
Plugin Name: NEOGATE Payment Gateway
Plugin URI: https://alrajhibank.com.sa
Description: Extends WooCommerce with NeoGate. Required PHP v7.3 or Higher.
Version: 4.3.0
Author: NeoGate
Copyright: © 2020 NeoGate. All rights reserved.
*/
if ( ! defined( 'ABSPATH' ) )
{
    exit;
}
$bd=ABSPATH.'wp-content/plugins/'.dirname( plugin_basename( __FILE__ ) );

add_action('plugins_loaded', 'woocommerce_neogate_init', 0);

function woocommerce_neogate_init() {

  if ( !class_exists( 'WC_Payment_Gateway' ) ) return;  
  /**
   * Localisation
   */
  load_plugin_textdomain('wc-neogate', false, dirname( plugin_basename( __FILE__ ) ) . '/languages');
  
  if(@$_GET['msg']!=''){
    add_action('the_content', 'showneogateMessage');
  }

  function showneogateMessage($content){
    return '<div class="box '.htmlentities($_GET['type']).'-box">'.htmlentities(urldecode($_GET['msg'])).'</div>'.$content;
  }
  /**
   * Gateway class
   */
  class WC_Neogate extends WC_Payment_Gateway {
    protected $msg = array();
	
	protected $logger;
	
	protected $AES_IV="PGKEYENCDECIVSPC"; //For Encryption/Decryption
	protected $AES_METHOD="AES-256-CBC";
	
    public function __construct(){
		global $wpdb;
      // Go wild in here
      $this -> id = 'neogate';
      $this -> method_title = __('NeoGate', 'neogate');
	  $this -> method_description = __('Pay securely by Credit or Debit card .', 'neogate');
      $this -> icon = WP_PLUGIN_URL . "/" . plugin_basename(dirname(__FILE__)) . '/images/Cardslogo.jpeg';
      $this -> has_fields = false;
      $this -> init_form_fields();
      $this -> init_settings();
      $this -> title = 'Pay Online'; //$this -> settings['title'];
      $this -> description = $this -> settings['description'];
      $this -> gateway_url = $this -> settings['gateway_url'];
      $this -> redirect_page_id = $this -> settings['redirect_page_id'];      
	  $this -> tranportalid = $this -> settings['tranportalid'];
	  $this -> tranportalpassword = $this -> settings['tranportalpassword'];
	  $this -> termresourcekey = $this -> settings['termresourcekey'];
	  $this -> encryption = $this -> settings['encryption'];
	  $this -> udf1 = $this -> settings['udf1'];
	  $this -> udf2 = $this -> settings['udf2'];
	  $this -> udf3 = $this -> settings['udf3'];
	  $this -> udf4 = $this -> settings['udf4'];
	  $this -> langid = $this -> settings['langid'];
	  $this -> msg['message'] = "";
      $this -> msg['class'] = "";
	
		
      add_action('init', array(&$this, 'check_neogate_response'));
      //update for woocommerce >2.0
      add_action( 'woocommerce_api_' . strtolower( get_class( $this ) ), array( $this, 'check_neogate_response' ) );

      add_action('valid-neogatebob-request', array(&$this, 'SUCCESS'));
			
      if ( version_compare( WOOCOMMERCE_VERSION, '2.0.0', '>=' ) ) {
        add_action( 'woocommerce_update_options_payment_gateways_' . $this->id, array( &$this, 'process_admin_options' ) );
      } else {
        add_action( 'woocommerce_update_options_payment_gateways', array( &$this, 'process_admin_options' ) );
      }
		
      add_action('woocommerce_receipt_neogate', array(&$this, 'receipt_page'));
      //add_action('woocommerce_thankyou_neogate',array(&$this, 'thankyou_page'));
	  //remove_action('woocommerce_thankyou_neogate',array(&$this, 'thankyou_page'));
      
	  $this->logger = wc_get_logger();
	  
	  if($this->settings['enabled']=='yes') //Update session cookies
		  $this->manage_session();	  
    }
    
	/**
	* Session patch CSRF Samesite=None; Secure
	**/
	function manage_session()
	{
		$context = array( 'source' => $this->id );
		try
		{
			if(PHP_VERSION_ID >= 70300)
			{
				$options = session_get_cookie_params();  
				$options['samesite'] = 'None';
				$options['secure'] = true;
				unset($options['lifetime']); 
				$cookies = $_COOKIE;  	
				foreach ($cookies as $key => $value)
				{
					if (!preg_match('/cart/', $key))
						setcookie($key, $value, $options);
				}
			}
			else {
				$this->logger->error( "NEOGATE payment plugin does not support this PHP version for cookie management. 
				Required PHP v7.3 or higher.", $context );
			}
		}
		catch(Exception $e) {
			$this->logger->error( $e->getMessage(), $context );
		}
	}
	
	
    function init_form_fields(){

      $this -> form_fields = array(
        'enabled' => array(
            'title' => __('Enable/Disable', 'neogate'),
            'type' => 'checkbox',
						'label' => __('Enable NeoGate', 'neogate'),
            'default' => 'no'),
		  'encryption' => array(
            'title' => __('Encryption Method', 'neogate'),
            'type' => 'select',
            'options' => array("aes"=>"AES-IV","tdes"=>"TDES"),
            'description' => __('AES-IV or Tripple DES','neogate')
            ),
          'gateway_url' => array(
            'title' => __('Gateway URL', 'neogate'),
            'type' => 'textarea',
            'description' => __('The URL to the hosted payment page of NEOGATE.', 'neogate'),
			'default' => __('https://securepayments.alrajhibank.com.sa/pg/PaymentHTTP.htm?param=paymentInit', 'neogate')
            ),
		  'tranportalid' => array(
            'title' => __('Portal ID', 'neogate'),
            'type' => 'text',
            'description' =>  __('Portal ID as provided', 'neogate')
            ),
		  'tranportalpassword' => array(
            'title' => __('Portal Password', 'neogate'),
            'type' => 'text',
            'description' =>  __('Portal Password as provided.', 'neogate')
            ),
		  'termresourcekey' => array(
            'title' => __('Terminal Resource Key', 'neogate'),
            'type' => 'text',
            'description' =>  __('Resource Key as provided.', 'neogate')
            ),
		  'udf1' => array(
            'title' => __('UDF1', 'neogate'),
            'type' => 'text',
            'description' =>  __('User Defined Field for custom parameters.', 'neogate')
            ),
		  'udf2' => array(
            'title' => __('UDF2', 'neogate'),
            'type' => 'text',
            'description' =>  __('User Defined Field for custom parameters.', 'neogate')
            ),
		  'udf3' => array(
            'title' => __('UDF3', 'neogate'),
            'type' => 'text',
            'description' =>  __('User Defined Field for custom parameters.', 'neogate')
            ),
		  'udf4' => array(
            'title' => __('UDF4', 'neogate'),
            'type' => 'text',
            'description' =>  __('User Defined Field for custom parameters.', 'neogate')
            ),
		  'udf5' => array(
            'title' => __('UDF5', 'neogate'),
            'type' => 'text',
            'description' =>  __('User Defined Field for custom parameters.', 'neogate')
            ),
		  'udf6' => array(
            'title' => __('UDF6', 'neogate'),
            'type' => 'text',
            'description' =>  __('User Defined Field for custom parameters.', 'neogate')
            ),
		  'udf7' => array(
            'title' => __('UDF7', 'neogate'),
            'type' => 'text',
            'description' =>  __('User Defined Field for custom parameters.', 'neogate')
            ),
		  'udf8' => array(
            'title' => __('UDF8', 'neogate'),
            'type' => 'text',
            'description' =>  __('User Defined Field for custom parameters.', 'neogate')
            ),
		  'udf9' => array(
            'title' => __('UDF9', 'neogate'),
            'type' => 'text',
            'description' =>  __('User Defined Field for custom parameters.', 'neogate')
            ),	
		  'udf10' => array(
            'title' => __('UDF10', 'neogate'),
            'type' => 'text',
            'description' =>  __('User Defined Field for custom parameters.', 'neogate')
            ),
		  'langid' => array(
            'title' => __('langid', 'neogate'),
            'type' => 'text',
            'description' =>  __('Payment Page Language.', 'neogate')
            ),			
          'redirect_page_id' => array(
            'title' => __('Return Page'),
            'type' => 'select',
            'options' => $this -> get_pages('Select Page'),
            'description' => "URL of Failure/Cancelled Page"
            )
		  );
    }
    
    /**
     * Admin Panel Options
     * - Options for bits like 'title' and availability on a country-by-country basis
     **/
    public function admin_options(){
      echo '<h3>'.__('NEOGATE', 'neogate').'</h3>';
      echo '<p>'.__('NEOGATE most popular payment gateways for online shopping.').'</p>';
	  echo '<script src="https://code.jquery.com/jquery-3.2.1.min.js"></script>';
	  if(PHP_VERSION_ID < 70300)
		  echo "<h1 style=\"color:red;\">**Notice: NEOGATE payment plugin requires PHP v7.3 or higher.<br />
	  Plugin will not work properly below PHP v7.3 due to SameSite cookie restriction.</h1>";
      echo '<table class="form-table">';
      $this -> generate_settings_html();
      echo '</table>';
	  
    }
		
    /**
     *  There are no payment fields, but we want to show the description if set.
     **/
    function payment_fields(){
      if($this -> description) echo wpautop(wptexturize($this -> description));
    }
		
    /**
     * Receipt Page
     **/
    function receipt_page($order){
		echo $lang=get_bloginfo("language");
		if (get_locale()=='ar'){
			      echo '<p>'.__('شكرا لطلبكم سيتم تحويلكم الى صفحة الدفع', 'neogate').'</p>';
		}
		else {
      echo '<p>'.__('Thank you for your order, please wait as you will be automatically redirected to Payment Page.', 'neogate').'</p>';
			
		}
      echo $this -> generate_neogate_form($order);
    }
    
    /**
     * Process the payment and return the result
     **/   
     function process_payment($order_id){
            $order = new WC_Order($order_id);

            if ( version_compare(WOOCOMMERCE_VERSION, '2.0.0', '>=' ) ) {
                return array(
                    'result' => 'success',
                    'redirect' => add_query_arg('order', $order->id,
                        add_query_arg('key', $order->get_order_key(), $order->get_checkout_payment_url(true)))
                );
            }
            else {
                return array(
                    'result' => 'success',
                    'redirect' => add_query_arg('order', $order->id,
                        add_query_arg('key', $order->get_order_key(), get_permalink(get_option('woocommerce_pay_page_id'))))
                );
            }
        }
    /**
     * Check for valid Citrus server callback
     **/    
    function check_neogate_response(){
      
		global $woocommerce;
		
		if (!isset($_GET['wc-api'])) {
			//invalid response	
			$this -> msg['class'] = 'error';
			$this -> msg['message'] = "Invalid payment gateway response...";
			wc_clear_notices();
			wc_add_notice( $this->msg['message'], $this->msg['class'] );
			
			//$redirect_url = add_query_arg( array('msg'=> urlencode($this -> msg['message']), 'type'=>$this -> msg['class']), $redirect_url );
			$redirect_url = ($this ->redirect_page_id=="" || $this -> redirect_page_id==0)?get_site_url() . "/":get_permalink($this -> redirect_page_id);

			wp_redirect( $redirect_url );
			exit;
		}
		
		$ResErrorText= (isset($_REQUEST['ErrorText'])? $_REQUEST['ErrorText'] : null); 	  	//Error Text/message
		$ResPaymentId = (isset($_REQUEST['PaymentID'])? $_REQUEST['PaymentID'] : null);		//Payment Id
		
		if($ResErrorText!=null)
		{
			//invalid response	
			$this -> msg['class'] = 'error';
			$this -> msg['message'] = "Error::".$ResErrorText;			
			wc_clear_notices();
			wc_add_notice( $this->msg['message'], $this->msg['class'] );
			
			//$redirect_url = add_query_arg( array('msg'=> urlencode($this -> msg['message']), 'type'=>$this -> msg['class']), $redirect_url );
			$redirect_url = ($this ->redirect_page_id=="" || $this -> redirect_page_id==0)?get_site_url() . "/":get_permalink($this -> redirect_page_id);

			wp_redirect( $redirect_url );
			exit;
		}
		
			
		$ResTranData= (isset($_REQUEST['trandata'])? $_REQUEST['trandata'] : null);
		if($ResTranData !=null)
		{
			//Decryption logice starts
			try
			{
				$decryptedData='';
				if($this->encryption == 'aes')
					$decrytedData=$this->decryptAES($ResTranData,$this->termresourcekey);
				elseif($this->encryption == 'tdes')
					$decrytedData=$this->decryptTDES($ResTranData,$this->termresourcekey);
				$res='';
				parse_str($decrytedData,$res);
				
				$ResPaymentId = $res['paymentid'];
				$ResResult = $res['result'];
				$ResAuth = $res['auth'];
				$ResAuthRespCode = $res['authRespCode'];
				$ResAVR = $res['avr'];
				$ResRef = $res['ref'];
				$ResTranId = $res['tranid'];
				$ResPostdate = $res['postdate'];
				$ResTrackID = $res['trackid'];
				$ResAmount = $res['amt'];
				$Resudf1 = $res['udf1'];
				$Resudf2 = $res['udf2'];
				$Resudf3 = $res['udf3'];
				$Resudf4 = $res['udf4'];
				$Resudf5 = $res['udf5'];	
				$Resudf6 = $res['udf6'];	
				$Resudf7 = $res['udf7'];	
				$Resudf8 = $res['udf8'];	
				$Resudf9 = $res['udf9'];	
				$Resudf10 = $res['udf10'];	
				
				$order_id = explode('_', $ResTrackID);
				$order_id = (int)$order_id[0];    //get rid of time part
				
				$order = new WC_Order($order_id);
				if (get_locale()=='ar'){
				$this -> msg['class'] = 'error';
				$this -> msg['message'] = ".شكرا لتسوقكم معنا, للاسف عملية الدفع فشلت";
				}else{
				$this -> msg['class'] = 'error';
				$this -> msg['message'] = "Thank you for shopping with us. However, the transaction has been declined.";
				}
				if (isset($ResResult) && strtoupper($ResResult) == 'CAPTURED' && $ResAuthRespCode == '00') {
					if (get_locale()=='ar'){
						$this -> msg['message'] = ":شكرا لتسوقكم معنا, عملية الدفع كانت ناجحة, وتفاصيل طلبكم بالاسفل 
								
							<br> 
								رقم الطلب: $order_id<br/>
								المبلغ: $ResAmount 
								<br />
								
									
						.سوف نقوم بشحن طلبكم قريبا";
					}
					else{
						$this -> msg['message'] = "Thank you for shopping with us. Your account has been charged and your transaction is successful with following order details: 
								
							<br> 
								Order Id: $order_id<br/>
								Amount: $ResAmount 
								<br />
								
									
						We will be shipping your order to you soon.";
					}
					
					$this -> msg['class'] = 'success';
								
					if($order -> status == 'processing' || $order -> status == 'completed' )
					{
						//do nothing
					}
					else
					{
						//complete the order
						$order -> payment_complete();
						$order -> add_order_note('Neogate has processed the payment. Ref Number: '.$ResPaymentId);
						$order -> add_order_note($this->msg['message']);
						$order -> add_order_note("Paid by Neogate");
						$woocommerce -> cart -> empty_cart();
					}
				}
			}
			catch(Exception $ex)
			{
				if (get_locale()=='ar'){
					$this -> msg['class'] = 'error';
				$this -> msg['message'] = " ...الرجاء المحاولة لاحقا.لا نستطيع تلبية طلبكم الان";
				}
				else{
					$this -> msg['class'] = 'error';
				$this -> msg['message'] = "Unable to process payment response. Probable Tamper Attempt...";
				}
				
			}
			
		}	
		
		//manage msessages
		if (function_exists('wc_add_notice')) {
			wc_clear_notices();
			if($this->msg['class']!='success'){
				wc_add_notice( $this->msg['message'], $this->msg['class'] );
			}
		}
		else {
			if($this->msg['class']!='success'){
				$woocommerce->add_error($this->msg['message']);				
			}
			else{
				//$woocommerce->add_message($this->msg['message']);
			}
			$woocommerce->set_messages();
		}
			
		$redirect_url = ($this ->redirect_page_id=="" || $this -> redirect_page_id==0)?get_site_url() . "/":get_permalink($this -> redirect_page_id);
		if($order && $this->msg['class'] == 'success') 
			$redirect_url = $order->get_checkout_order_received_url();
		
		//For wooCoomerce 2.0
		//$redirect_url = add_query_arg( array('msg'=> urlencode($this -> msg['message']), 'type'=>$this -> msg['class']), $redirect_url );
		wp_redirect( $redirect_url );
		exit;
			
    }
    
    
    
    /**
     * Generate button link
     **/    
    public function generate_neogate_form($order_id){
      
		global $woocommerce;
		$order = new WC_Order($order_id);
		$redirect_url = ($this -> redirect_page_id=="" || $this -> redirect_page_id==0)?get_site_url() . "/":get_permalink($this -> redirect_page_id);
      
		//For wooCoomerce 2.0
		$redirect_url = add_query_arg( 'wc-api', get_class( $this ), $redirect_url );	
		
		//$order_id = $order_id.'_'.date("ymd");
      
		//do we have a phone number?
		//get currency      
		$baddress = $order -> billing_address_1;
		if ($order -> billing_address_2 != "")
		$baddress = $baddress.' '.$order -> billing_address_2;
	
		$saddress = $order -> shipping_address_1;
		if ($order -> shipping_address_2 != "")
		$saddress = $saddress.' '.$order -> shipping_address_2;
      	
		$country= self::countryArray[$order->get_shipping_country()];
		$currency = self::currencyArray[$order->get_currency()];		
		
		$ReqAction = "action=1&"; //Purchase only
		$ReqAmount = "amt=".$order -> order_total."&";
		$ReqTrackId = "trackid=".$order_id.'_'.(int)microtime(true)."&";
		$ReqTranportalId = "id=".$this->tranportalid."&";
		$ReqTranportalPassword = "password=".$this->tranportalpassword."&";
		$ReqCurrency = "currencycode=".$currency['code']."&"; 
		$ReqLangid = "langid=".$this->langid."&";
	
		/* Shipping */
		$Reqship_To_Postalcd = "ship_To_Postalcd=".$order->shipping_postcode."&";
		$Reqship_To_Address = "ship_To_Address=".$saddress."&";
		$Reqship_To_LastName = "ship_To_LastName=".$order->shipping_last_name."&";
		$Reqship_To_FirstName = "ship_To_FirstName=".$order->shipping_first_name."&";
		$Reqship_To_Phn_Num = "ship_To_Phn_Num=".$order->billing_phone."&";
		$Reqship_To_CountryCd = "ship_To_CountryCd=".$country['code']."&"; 
		
		/* Card Holder Details */
		$Reqcard_PostalCd = "card_PostalCd=".$order -> billing_postcode."&";
		$Reqcard_Address = "card_Address=".$baddress."&";
		$Reqcard_Phn_Num = "card_Phn_Num=".$order -> billing_phone."&";
		$Reqcust_email = "cust_email=".$order -> billing_email."&";
	
		$ReqResponseUrl = "&responseURL=".$redirect_url."&";
		$ReqErrorUrl = "&errorURL=".$redirect_url."&";
	
		$ReqUdf1 = "udf1=Test1&";	// UDF1 values 
		$ReqUdf2 = "udf2="."Test2"."&";	// UDF2 values 
		$ReqUdf3 = "udf3="."Test3"."&";	// UDF3 values 
		$ReqUdf4 = "udf4="."Test4&";
		$ReqUdf5 = "udf5="."Test5&"; 
		$ReqUdf6 = "udf6="."Test6&"; 
		$ReqUdf7 = "udf7="."Test7&"; 
		$ReqUdf8 = "udf8="."Test8&"; 
		$ReqUdf9 = "udf9="."Test9&"; 
		$ReqUdf10 = "udf10="."Test10&";
				
	
		if($this->udf1 !="")
			$ReqUdf1 = "udf1=".$this->udf1."&";
		if($this->udf2 !="")
			$ReqUdf2 = "udf2=".$this->udf2."&";
		if($this->udf3 !="")
			$ReqUdf3 = "udf3=".$this->udf3."&";
		if($this->udf4 !="")
			$ReqUdf4 = "udf4=".$this->udf4."&";
		if($this->udf5 !="")
			$ReqUdf5 = "udf5=".$this->udf5."&";
		if($this->udf6 !="")
			$ReqUdf6 = "udf6=".$this->udf6."&";
		if($this->udf7 !="")
			$ReqUdf7 = "udf7=".$this->udf7."&";
		if($this->udf8 !="")
			$ReqUdf8 = "udf8=".$this->udf8."&";
		if($this->udf9 !="")
			$ReqUdf9 = "udf9=".$this->udf9."&";
		if($this->udf10 !="")
			$ReqUdf10 = "udf10=".$this->udf10."&";
	
		$TranRequest=$ReqAmount.$ReqAction.$ReqResponseUrl.$ReqErrorUrl.$ReqTrackId.$ReqCurrency.$ReqLangid.$ReqTranportalId.$ReqTranportalPassword.
		$Reqship_To_Postalcd.$Reqship_To_Address.$Reqship_To_LastName.$Reqship_To_FirstName.$Reqship_To_Phn_Num.$Reqship_To_CountryCd.$Reqcard_PostalCd.
		$Reqcard_Address.$Reqcard_Phn_Num.$Reqcust_email.$ReqUdf1.$ReqUdf2.$ReqUdf3.$ReqUdf4.$ReqUdf5.$ReqUdf6.$ReqUdf7.$ReqUdf8.$ReqUdf9.$ReqUdf10;
		
		//echo  $TranRequest ;		 
		//exit();
		$req='';
		if($this->encryption == 'aes')
			$req = "&trandata=".$this->encryptAES($TranRequest,$this->termresourcekey);
		elseif($this->encryption == 'tdes')
			$req = "&trandata=".$this->encryptTDES($TranRequest,$this->termresourcekey);
		  
		$req = $req.$ReqErrorUrl.$ReqResponseUrl."&tranportalId=".$this->tranportalid;
		  
		//echo $this->gateway_url . $req ;
		  
		$html= '<script language="javascript">window.location.href ="'.$this->gateway_url.$req.'";</script>';
			
		return $html;
			
		
    }
    
        
    function get_pages($title = false, $indent = true) {
      $wp_pages = get_pages('sort_column=menu_order');
      $page_list = array();
      if ($title) $page_list[] = $title;
      foreach ($wp_pages as $page) {
        $prefix = '';
        // show indented child pages?
        if ($indent) {
          $has_parent = $page->post_parent;
          while($has_parent) {
            $prefix .=  ' - ';
            $next_page = get_page($has_parent);
            $has_parent = $next_page->post_parent;
          }
        }
        // add to page list array array
        $page_list[$page->ID] = $prefix . $page->post_title;
      }
      return $page_list;
    }
	
	/* AES IV 256 Bit  Encryption/Decryption Methods */
	function encryptAES($str,$key) {		
		$str = $this->pkcs5_pad($str); 
		$encrypted = openssl_encrypt($str, $this->AES_METHOD, $key, OPENSSL_ZERO_PADDING, $this->AES_IV);
		$encrypted = base64_decode($encrypted);
		$encrypted = unpack('C*', ($encrypted));
		$encrypted = $this->byteArray2Hex($encrypted);
		$encrypted = urlencode($encrypted);
		return $encrypted;
	}
	
	function decryptAES($code,$key) { 		
		$code = $this->hex2ByteArray(trim($code));
		$code= $this->byteArray2String($code);	  
		$code = base64_encode($code);
		$decrypted = openssl_decrypt($code, $this->AES_METHOD, $key, OPENSSL_ZERO_PADDING, $this->AES_IV);
		return $this->pkcs5_unpad($decrypted);
	}
	
	function pkcs5_pad ($text) {
		$blocksize = openssl_cipher_iv_length($this->AES_METHOD);
		$pad = $blocksize - (strlen($text) % $blocksize);
		return $text . str_repeat(chr($pad), $pad);
	}
	
	function pkcs5_unpad($text) {
		$pad = ord($text[strlen($text)-1]);
		if ($pad > strlen($text)) {
			return false;	
		}
		if (strspn($text, chr($pad), strlen($text) - $pad) != $pad) {
			return false;
		}
		return substr($text, 0, -1 * $pad);
    }
	
	function byteArray2Hex($byteArray) {
		$chars = array_map("chr", $byteArray);
		$bin = join($chars);
		return bin2hex($bin);
	}
	
	function hex2ByteArray($hexString) {
		$string = hex2bin($hexString);
		return unpack('C*', $string);
	}
	
	function byteArray2String($byteArray) {
		$chars = array_map("chr", $byteArray);
		return join($chars);
	}
	
	// TDES Functions start
	function encryptTDES($payload, $key) {  
		$chiper = "DES-EDE3-CBC";  //Algorthim used to encrypt
		if((strlen($payload)%8)!=0) {
			//Perform right padding
			$payload = $this->rightPadZeros($payload);
		}
		$iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($chiper));
		$encrypted = openssl_encrypt($payload, $chiper, $key,OPENSSL_RAW_DATA,$iv);
		
		$encrypted=unpack('C*', ($encrypted));
		$encrypted=$this->byteArray2Hex($encrypted);
		return strtoupper($encrypted);  
	}
	
	function decryptTDES($data, $key) {
		$chiper = "DES-EDE3-CBC";  //Algorthim used to decrypt
		$data = $this->hex2ByteArray($data);
		$data = $this->byteArray2String($data);
		$data = base64_encode($data);
		$iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($chiper));
		$decrypted = openssl_decrypt($data, $chiper, $key, OPENSSL_ZERO_PADDING,$iv);
		return $decrypted;
	} 
	
	function rightPadZeros($Str) {
		if(null == $Str){
			return null;
		}
		$PadStr = $Str;
		
		for ($i = strlen($Str);($i%8)!=0; $i++) {
			$PadStr .= "^";
		}
		return $PadStr;
	}
	// TDES Functions end
	//End of Encryption/Decryption methods
	
	const countryArray = array(
	'AF'=>array('name'=>'Afghanistan','code'=>'004'),
	'AX'=>array('name'=>'Ã…land Islands','code'=>'248'),
	'AL'=>array('name'=>'Albania','code'=>'008'),
	'DZ'=>array('name'=>'Algeria','code'=>'012'),
	'AS'=>array('name'=>'American Samoa','code'=>'016'),
	'AD'=>array('name'=>'Andorra','code'=>'020'),
	'AO'=>array('name'=>'Angola','code'=>'024'),
	'AI'=>array('name'=>'Anguilla','code'=>'660'),
	'AQ'=>array('name'=>'Antarcticaâ€Š[a]','code'=>'010'),
	'AG'=>array('name'=>'Antigua and Barbuda','code'=>'028'),
	'AR'=>array('name'=>'Argentina','code'=>'032'),
	'AM'=>array('name'=>'Armenia','code'=>'051'),
	'AW'=>array('name'=>'Aruba','code'=>'533'),
	'AU'=>array('name'=>'Australiaâ€Š[b]','code'=>'036'),
	'AT'=>array('name'=>'Austria','code'=>'040'),
	'AZ'=>array('name'=>'Azerbaijan','code'=>'031'),
	'BS'=>array('name'=>'Bahamas (the)','code'=>'044'),
	'BH'=>array('name'=>'Bahrain','code'=>'048'),
	'BD'=>array('name'=>'Bangladesh','code'=>'050'),
	'BB'=>array('name'=>'Barbados','code'=>'052'),
	'BY'=>array('name'=>'Belarus','code'=>'112'),
	'BE'=>array('name'=>'Belgium','code'=>'056'),
	'BZ'=>array('name'=>'Belize','code'=>'084'),
	'BJ'=>array('name'=>'Benin','code'=>'204'),
	'BM'=>array('name'=>'Bermuda','code'=>'060'),
	'BT'=>array('name'=>'Bhutan','code'=>'064'),
	'BO'=>array('name'=>'Bolivia (Plurinational State of)','code'=>'068'),
	'BQ'=>array('name'=>'Bonaire','code'=>'535'),
	'BA'=>array('name'=>'Bosnia and Herzegovina','code'=>'070'),
	'BW'=>array('name'=>'Botswana','code'=>'072'),
	'BV'=>array('name'=>'Bouvet Island','code'=>'074'),
	'BR'=>array('name'=>'Brazil','code'=>'076'),
	'IO'=>array('name'=>'British Indian Ocean Territory (the)','code'=>'086'),
	'BN'=>array('name'=>'Brunei Darussalamâ€Š[e]','code'=>'096'),
	'BG'=>array('name'=>'Bulgaria','code'=>'100'),
	'BF'=>array('name'=>'Burkina Faso','code'=>'854'),
	'BI'=>array('name'=>'Burundi','code'=>'108'),
	'CV'=>array('name'=>'Cabo Verdeâ€Š[f]','code'=>'132'),
	'KH'=>array('name'=>'Cambodia','code'=>'116'),
	'CM'=>array('name'=>'Cameroon','code'=>'120'),
	'CA'=>array('name'=>'Canada','code'=>'124'),
	'KY'=>array('name'=>'Cayman Islands (the)','code'=>'136'),
	'CF'=>array('name'=>'Central African Republic (the)','code'=>'140'),
	'TD'=>array('name'=>'Chad','code'=>'148'),
	'CL'=>array('name'=>'Chile','code'=>'152'),
	'CN'=>array('name'=>'China','code'=>'156'),
	'CX'=>array('name'=>'Christmas Island','code'=>'162'),
	'CC'=>array('name'=>'Cocos (Keeling) Islands (the)','code'=>'166'),
	'CO'=>array('name'=>'Colombia','code'=>'170'),
	'KM'=>array('name'=>'Comoros (the)','code'=>'174'),
	'CD'=>array('name'=>'Congo (the Democratic Republic of the)','code'=>'180'),
	'CG'=>array('name'=>'Congo (the)â€Š[g]','code'=>'178'),
	'CK'=>array('name'=>'Cook Islands (the)','code'=>'184'),
	'CR'=>array('name'=>'Costa Rica','code'=>'188'),
	'CI'=>array('name'=>'CÃ´te dIvoire','code'=>'384'),
	'HR'=>array('name'=>'Croatia','code'=>'191'),
	'CU'=>array('name'=>'Cuba','code'=>'192'),
	'CW'=>array('name'=>'CuraÃ§ao','code'=>'531'),
	'CY'=>array('name'=>'Cyprus','code'=>'196'),
	'CZ'=>array('name'=>'Czechiaâ€Š[i]','code'=>'203'),
	'DK'=>array('name'=>'Denmark','code'=>'208'),
	'DJ'=>array('name'=>'Djibouti','code'=>'262'),
	'DM'=>array('name'=>'Dominica','code'=>'212'),
	'DO'=>array('name'=>'Dominican Republic (the)','code'=>'214'),
	'EC'=>array('name'=>'Ecuador','code'=>'218'),
	'EG'=>array('name'=>'Egypt','code'=>'818'),
	'SV'=>array('name'=>'El Salvador','code'=>'222'),
	'GQ'=>array('name'=>'Equatorial Guinea','code'=>'226'),
	'ER'=>array('name'=>'Eritrea','code'=>'232'),
	'EE'=>array('name'=>'Estonia','code'=>'233'),
	'SZ'=>array('name'=>'Eswatiniâ€Š[j]','code'=>'748'),
	'ET'=>array('name'=>'Ethiopia','code'=>'231'),
	'FK'=>array('name'=>'Falkland Islands (the) [Malvinas]â€Š[k]','code'=>'238'),
	'FO'=>array('name'=>'Faroe Islands (the)','code'=>'234'),
	'FJ'=>array('name'=>'Fiji','code'=>'242'),
	'FI'=>array('name'=>'Finland','code'=>'246'),
	'FR'=>array('name'=>'Franceâ€Š[l]','code'=>'250'),
	'GF'=>array('name'=>'French Guiana','code'=>'254'),
	'PF'=>array('name'=>'French Polynesia','code'=>'258'),
	'TF'=>array('name'=>'French Southern Territories (the)â€Š[m]','code'=>'260'),
	'GA'=>array('name'=>'Gabon','code'=>'266'),
	'GM'=>array('name'=>'Gambia (the)','code'=>'270'),
	'GE'=>array('name'=>'Georgia','code'=>'268'),
	'DE'=>array('name'=>'Germany','code'=>'276'),
	'GH'=>array('name'=>'Ghana','code'=>'288'),
	'GI'=>array('name'=>'Gibraltar','code'=>'292'),
	'GR'=>array('name'=>'Greece','code'=>'300'),
	'GL'=>array('name'=>'Greenland','code'=>'304'),
	'GD'=>array('name'=>'Grenada','code'=>'308'),
	'GP'=>array('name'=>'Guadeloupe','code'=>'312'),
	'GU'=>array('name'=>'Guam','code'=>'316'),
	'GT'=>array('name'=>'Guatemala','code'=>'320'),
	'GG'=>array('name'=>'Guernsey','code'=>'831'),
	'GN'=>array('name'=>'Guinea','code'=>'324'),
	'GW'=>array('name'=>'Guinea-Bissau','code'=>'624'),
	'GY'=>array('name'=>'Guyana','code'=>'328'),
	'HT'=>array('name'=>'Haiti','code'=>'332'),
	'HM'=>array('name'=>'Heard Island and McDonald Islands','code'=>'334'),
	'VA'=>array('name'=>'Holy See (the)â€Š[n]','code'=>'336'),
	'HN'=>array('name'=>'Honduras','code'=>'340'),
	'HK'=>array('name'=>'Hong Kong','code'=>'344'),
	'HU'=>array('name'=>'Hungary','code'=>'348'),
	'IS'=>array('name'=>'Iceland','code'=>'352'),
	'IN'=>array('name'=>'India','code'=>'356'),
	'ID'=>array('name'=>'Indonesia','code'=>'360'),
	'IR'=>array('name'=>'Iran (Islamic Republic of)','code'=>'364'),
	'IQ'=>array('name'=>'Iraq','code'=>'368'),
	'IE'=>array('name'=>'Ireland','code'=>'372'),
	'IM'=>array('name'=>'Isle of Man','code'=>'833'),
	'IL'=>array('name'=>'Israel','code'=>'376'),
	'IT'=>array('name'=>'Italy','code'=>'380'),
	'JM'=>array('name'=>'Jamaica','code'=>'388'),	
	'JP'=>array('name'=>'Japan','code'=>'392'),
	'JE'=>array('name'=>'Jersey','code'=>'832'),
	'JO'=>array('name'=>'Jordan','code'=>'400'),
	'KZ'=>array('name'=>'Kazakhstan','code'=>'398'),
	'KE'=>array('name'=>'Kenya','code'=>'404'),
	'KI'=>array('name'=>'Kiribati','code'=>'296'),
	'KP'=>array('name'=>'Korea','code'=>'408'),
	'KR'=>array('name'=>'Korea (the Republic of)â€Š[p]','code'=>'410'),
	'KW'=>array('name'=>'Kuwait','code'=>'414'),
	'KG'=>array('name'=>'Kyrgyzstan','code'=>'417'),
	'LA'=>array('name'=>'Lao Peoples Democratic Republic','code'=>'418'),
	'LV'=>array('name'=>'Latvia','code'=>'428'),
	'LB'=>array('name'=>'Lebanon','code'=>'422'),
	'LS'=>array('name'=>'Lesotho','code'=>'426'),
	'LR'=>array('name'=>'Liberia','code'=>'430'),
	'LY'=>array('name'=>'Libya','code'=>'434'),
	'LI'=>array('name'=>'Liechtenstein','code'=>'438'),
	'LT'=>array('name'=>'Lithuania','code'=>'440'),
	'LU'=>array('name'=>'Luxembourg','code'=>'442'),
	'MO'=>array('name'=>'Macaoâ€Š[r]','code'=>'446'),
	'MK'=>array('name'=>'North Macedoniaâ€Š[s]','code'=>'807'),
	'MG'=>array('name'=>'Madagascar','code'=>'450'),
	'MW'=>array('name'=>'Malawi','code'=>'454'),
	'MY'=>array('name'=>'Malaysia','code'=>'458'),
	'MV'=>array('name'=>'Maldives','code'=>'462'),
	'ML'=>array('name'=>'Mali','code'=>'466'),
	'MT'=>array('name'=>'Malta','code'=>'470'),
	'MH'=>array('name'=>'Marshall Islands (the)','code'=>'584'),
	'MQ'=>array('name'=>'Martinique','code'=>'474'),
	'MR'=>array('name'=>'Mauritania','code'=>'478'),
	'MU'=>array('name'=>'Mauritius','code'=>'480'),
	'YT'=>array('name'=>'Mayotte','code'=>'175'),
	'MX'=>array('name'=>'Mexico','code'=>'484'),
	'FM'=>array('name'=>'Micronesia (Federated States of)','code'=>'583'),
	'MD'=>array('name'=>'Moldova (the Republic of)','code'=>'498'),
	'MC'=>array('name'=>'Monaco','code'=>'492'),
	'MN'=>array('name'=>'Mongolia','code'=>'496'),
	'ME'=>array('name'=>'Montenegro','code'=>'499'),
	'MS'=>array('name'=>'Montserrat','code'=>'500'),
	'MA'=>array('name'=>'Morocco','code'=>'504'),
	'MZ'=>array('name'=>'Mozambique','code'=>'508'),
	'MM'=>array('name'=>'Myanmarâ€Š[t]','code'=>'104'),
	'NA'=>array('name'=>'Namibia','code'=>'516'),
	'NR'=>array('name'=>'Nauru','code'=>'520'),
	'NP'=>array('name'=>'Nepal','code'=>'524'),
	'NL'=>array('name'=>'Netherlands (the)','code'=>'528'),
	'NC'=>array('name'=>'New Caledonia','code'=>'540'),
	'NZ'=>array('name'=>'New Zealand','code'=>'554'),
	'NI'=>array('name'=>'Nicaragua','code'=>'558'),
	'NE'=>array('name'=>'Niger (the)','code'=>'562'),
	'NG'=>array('name'=>'Nigeria','code'=>'566'),
	'NU'=>array('name'=>'Niue','code'=>'570'),
	'NF'=>array('name'=>'Norfolk Island','code'=>'574'),
	'MP'=>array('name'=>'Northern Mariana Islands (the)','code'=>'580'),
	'NO'=>array('name'=>'Norway','code'=>'578'),
	'OM'=>array('name'=>'Oman','code'=>'512'),
	'PK'=>array('name'=>'Pakistan','code'=>'586'),
	'PW'=>array('name'=>'Palau','code'=>'585'),
	'PS'=>array('name'=>'Palestine, State of','code'=>'275'),
	'PA'=>array('name'=>'Panama','code'=>'591'),
	'PG'=>array('name'=>'Papua New Guinea','code'=>'598'),
	'PY'=>array('name'=>'Paraguay','code'=>'600'),
	'PE'=>array('name'=>'Peru','code'=>'604'),
	'PH'=>array('name'=>'Philippines (the)','code'=>'608'),
	'PN'=>array('name'=>'Pitcairnâ€Š[u]','code'=>'612'),
	'PL'=>array('name'=>'Poland','code'=>'616'),
	'PT'=>array('name'=>'Portugal','code'=>'620'),
	'PR'=>array('name'=>'Puerto Rico','code'=>'630'),
	'QA'=>array('name'=>'Qatar','code'=>'634'),
	'RE'=>array('name'=>'RÃ©union','code'=>'638'),
	'RO'=>array('name'=>'Romania','code'=>'642'),
	'RU'=>array('name'=>'Russian Federation (the)â€Š[v]','code'=>'643'),
	'RW'=>array('name'=>'Rwanda','code'=>'646'),
	'BL'=>array('name'=>'Saint BarthÃ©lemy','code'=>'652'),
	'SH'=>array('name'=>'Saint Helena, Ascension and Tristan da Cunha','code'=>'654'),
	'KN'=>array('name'=>'Saint Kitts and Nevis','code'=>'659'),
	'LC'=>array('name'=>'Saint Lucia','code'=>'662'),
	'MF'=>array('name'=>'Saint Martin (French part)','code'=>'663'),
	'PM'=>array('name'=>'Saint Pierre and Miquelon','code'=>'666'),
	'VC'=>array('name'=>'Saint Vincent and the Grenadines','code'=>'670'),
	'WS'=>array('name'=>'Samoa','code'=>'882'),
	'SM'=>array('name'=>'San Marino','code'=>'674'),
	'ST'=>array('name'=>'Sao Tome and Principe','code'=>'678'),
	'SA'=>array('name'=>'Saudi Arabia','code'=>'682'),
	'SN'=>array('name'=>'Senegal','code'=>'686'),
	'RS'=>array('name'=>'Serbia','code'=>'688'),
	'SC'=>array('name'=>'Seychelles','code'=>'690'),
	'SL'=>array('name'=>'Sierra Leone','code'=>'694'),
	'SG'=>array('name'=>'Singapore','code'=>'702'),
	'SX'=>array('name'=>'Sint Maarten (Dutch part)','code'=>'534'),
	'SK'=>array('name'=>'Slovakia','code'=>'703'),
	'SI'=>array('name'=>'Slovenia','code'=>'705'),
	'SB'=>array('name'=>'Solomon Islands','code'=>'90'),
	'SO'=>array('name'=>'Somalia','code'=>'706'),
	'ZA'=>array('name'=>'South Africa','code'=>'710'),
	'GS'=>array('name'=>'South Georgia and the South Sandwich Islands','code'=>'239'),
	'SS'=>array('name'=>'South Sudan','code'=>'728'),
	'ES'=>array('name'=>'Spain','code'=>'724'),
	'LK'=>array('name'=>'Sri Lanka','code'=>'144'),
	'SD'=>array('name'=>'Sudan (the)','code'=>'729'),
	'SR'=>array('name'=>'Suriname','code'=>'740'),
	'SJ'=>array('name'=>'Svalbard','code'=>'744'),
	'SE'=>array('name'=>'Sweden','code'=>'752'),
	'CH'=>array('name'=>'Switzerland','code'=>'756'),
	'SY'=>array('name'=>'Syrian Arab Republic (the)â€Š[x]','code'=>'760'),
	'TW'=>array('name'=>'Taiwan (Province of China)â€Š[y]','code'=>'158'),
	'TJ'=>array('name'=>'Tajikistan','code'=>'762'),
	'TZ'=>array('name'=>'Tanzania, the United Republic of','code'=>'834'),
	'TH'=>array('name'=>'Thailand','code'=>'764'),
	'TL'=>array('name'=>'Timor-Lesteâ€Š[aa]','code'=>'626'),
	'TG'=>array('name'=>'Togo','code'=>'768'),
	'TK'=>array('name'=>'Tokelau','code'=>'772'),
	'TO'=>array('name'=>'Tonga','code'=>'776'),
	'TT'=>array('name'=>'Trinidad and Tobago','code'=>'780'),
	'TN'=>array('name'=>'Tunisia','code'=>'788'),
	'TR'=>array('name'=>'Turkey','code'=>'792'),
	'TM'=>array('name'=>'Turkmenistan','code'=>'795'),
	'TC'=>array('name'=>'Turks and Caicos Islands (the)','code'=>'796'),
	'TV'=>array('name'=>'Tuvalu','code'=>'798'),
	'UG'=>array('name'=>'Uganda','code'=>'800'),
	'UA'=>array('name'=>'Ukraine','code'=>'804'),
	'AE'=>array('name'=>'United Arab Emirates (the)','code'=>'784'),
	'GB'=>array('name'=>'United Kingdom of Great Britain and Northern Ireland (the)','code'=>'826'),
	'UM'=>array('name'=>'United States Minor Outlying Islands (the)â€Š[ac]','code'=>'581'),
	'US'=>array('name'=>'United States of America (the)','code'=>'840'),
	'UY'=>array('name'=>'Uruguay','code'=>'858'),
	'UZ'=>array('name'=>'Uzbekistan','code'=>'860'),
	'VU'=>array('name'=>'Vanuatu','code'=>'548'),
	'VE'=>array('name'=>'Venezuela (Bolivarian Republic of)','code'=>'862'),
	'VN'=>array('name'=>'Viet Namâ€Š[ae]','code'=>'704'),
	'VG'=>array('name'=>'Virgin Islands (British)â€Š[af]','code'=>'92'),
	'VI'=>array('name'=>'Virgin Islands (U.S.)â€Š[ag]','code'=>'850'),
	'WF'=>array('name'=>'Wallis and Futuna','code'=>'876'),
	'EH'=>array('name'=>'Western Saharaâ€Š[ah]','code'=>'732'),
	'YE'=>array('name'=>'Yemen','code'=>'887'),
	'ZM'=>array('name'=>'Zambia','code'=>'894'),
	'ZW'=>array('name'=>'Zimbabwe','code'=>'716')
	);
	
	const currencyArray = array(
	'AFA'=>array('name'=>'Afghanistan Afghani','code'=>'004'),
	'ALL'=>array('name'=>'Albanian Lek','code'=>'008'),
	'DZD'=>array('name'=>'Algerian Dinar','code'=>'012'),
	'USD'=>array('name'=>'US Dollar','code'=>'840'),
	'ESP'=>array('name'=>'Spanish Peseta','code'=>'724'),
	'FRF'=>array('name'=>'French Franc','code'=>'250'),
	'ADP'=>array('name'=>'Andorran Peseta','code'=>'020'),
	'AOA'=>array('name'=>'Kwanza','code'=>'973'),
	'XCD'=>array('name'=>'East Caribbean Dollar','code'=>'951'),
	'XCD'=>array('name'=>'East Caribbean Dollar','code'=>'951'),
	'ARS'=>array('name'=>'Argentine Peso','code'=>'032'),
	'AMD'=>array('name'=>'Armenian Dram','code'=>'051'),
	'AWG'=>array('name'=>'Aruban Guilder','code'=>'533'),
	'AUD'=>array('name'=>'Australian Dollar','code'=>'036'),
	'ATS'=>array('name'=>'Austrian Schilling','code'=>'040'),
	'AZM'=>array('name'=>'Azerbaijanian Manat','code'=>'031'),
	'BSD'=>array('name'=>'Bahamian Dollar','code'=>'044'),
	'BHD'=>array('name'=>'Bahraini Dinar','code'=>'048'),
	'BDT'=>array('name'=>'Bangladeshi Taka','code'=>'050'),
	'BBD'=>array('name'=>'Barbados Dollar','code'=>'052'),
	'BYB'=>array('name'=>'Belarussian Ruble','code'=>'112'),
	'RYR'=>array('name'=>'Belarussian Ruble','code'=>'974'),
	'BEF'=>array('name'=>'Belgian Franc','code'=>'056'),
	'BZD'=>array('name'=>'Belize Dollar','code'=>'084'),
	'XOF'=>array('name'=>'CFA Franc (BCEAO)','code'=>'952'),
	'BMD'=>array('name'=>'Bermuda Dollar','code'=>'060'),
	'INR'=>array('name'=>'Indian Rupee','code'=>'356'),
	'BTN'=>array('name'=>'Ngultrum','code'=>'064'),
	'BOB'=>array('name'=>'Boliviano','code'=>'068'),
	'BOV'=>array('name'=>'Mvdol','code'=>'984'),
	'BAM'=>array('name'=>'Convertible Marks','code'=>'977'),
	'BWP'=>array('name'=>'Pula','code'=>'072'),
	'NOK'=>array('name'=>'Norwegian Krone','code'=>'578'),
	'BRL'=>array('name'=>'Brazil Real','code'=>'986'),	
	'BND'=>array('name'=>'Brunei Dollar','code'=>'096'),
	'BGL'=>array('name'=>'Lev','code'=>'100'),
	'BGN'=>array('name'=>'Bulgarian Lev','code'=>'975'),	
	'BIF'=>array('name'=>'Burundi Franc','code'=>'108'),
	'KHR'=>array('name'=>'Cambodian Riel','code'=>'116'),
	'XAF'=>array('name'=>'CFA Franc (BEAC)','code'=>'950'),
	'CAD'=>array('name'=>'Canadian Dollar','code'=>'124'),
	'CVE'=>array('name'=>'Cape Verde Escudo','code'=>'132'),
	'KYD'=>array('name'=>'Cayman Islands Dollar','code'=>'136'),
	'XAF'=>array('name'=>'CFA Franc (BEAC)','code'=>'950'),
	'XAF'=>array('name'=>'CFA Franc (BEAC)','code'=>'950'),
	'CLP'=>array('name'=>'Chilean Peso','code'=>'152'),
	'CLF'=>array('name'=>'Unidates de fomento','code'=>'990'),
	'CNY'=>array('name'=>'Yuan Renminbi','code'=>'156'),
	'HKD'=>array('name'=>'Hong Kong Dollar','code'=>'344'),
	'MOP'=>array('name'=>'Pataca','code'=>'446'),	
	'COP'=>array('name'=>'Colombian Peso','code'=>'170'),
	'KMF'=>array('name'=>'Comoro Franc','code'=>'174'),
	'XAF'=>array('name'=>'CFA Franc (BEAC)','code'=>'950'),
	'CDF'=>array('name'=>'Franc Congolais','code'=>'976'),
	'NZD'=>array('name'=>'New Zealand Dollar','code'=>'554'),
	'CRC'=>array('name'=>'Costa Rican Colon','code'=>'188'),	
	'HRK'=>array('name'=>'Croatian Kuna','code'=>'191'),
	'CUP'=>array('name'=>'Cuban Peso','code'=>'192'),
	'CYP'=>array('name'=>'Cyprus Pound','code'=>'196'),
	'CZK'=>array('name'=>'Czech Koruna','code'=>'203'),
	'DKK'=>array('name'=>'Danish Krone','code'=>'208'),
	'DJF'=>array('name'=>'Djibouti Franc','code'=>'262'),
	'XCD'=>array('name'=>'East Caribbean Dollar','code'=>'951'),
	'DOP'=>array('name'=>'Dominican Peso','code'=>'214'),
	'TPE'=>array('name'=>'Timor Escudo','code'=>'626'),
	'IDE'=>array('name'=>'Rupiah','code'=>'360'),
	'ECS'=>array('name'=>'Sucre','code'=>'218'),
	'ECV'=>array('name'=>'Unidad de Valor Constante (UVC)','code'=>'983'),
	'EGP'=>array('name'=>'Egyptian Pound','code'=>'818'),
	'SVC'=>array('name'=>'El Salvador Colon','code'=>'222'),
	'XAF'=>array('name'=>'CFA Franc (BEAC)','code'=>'950'),
	'ERN'=>array('name'=>'Nafka','code'=>'232'),
	'EEK'=>array('name'=>'Kroon','code'=>'233'),
	'ETB'=>array('name'=>'Ethiopian Birr','code'=>'230'),
	'DKK'=>array('name'=>'Danish Krone','code'=>'208'),
	'XEU'=>array('name'=>'euro','code'=>'954'),
	'EUR'=>array('name'=>'European Currency Unit','code'=>'978'),
	'FKP'=>array('name'=>'Falkland Islands Pound','code'=>'238'),
	'FJD'=>array('name'=>'Fiji Dollar','code'=>'242'),
	'FIM'=>array('name'=>'Finnish Markka','code'=>'246'),
	'FRF'=>array('name'=>'French Franc','code'=>'250'),
	'FRF'=>array('name'=>'French Franc','code'=>'250'),
	'XPF'=>array('name'=>'CFP Franc','code'=>'953'),
	'XPF'=>array('name'=>'CFP Franc','code'=>'953'),
	'XAF'=>array('name'=>'CFA Franc (BEAC)','code'=>'950'),
	'GMD'=>array('name'=>'Dalasi','code'=>'270'),
	'GEL'=>array('name'=>'Lari','code'=>'981'),
	'DEM'=>array('name'=>'Deutsche Mark','code'=>'276'),
	'GHC'=>array('name'=>'Ghana Cedi','code'=>'288'),
	'GIP'=>array('name'=>'Gibraltar Pound','code'=>'292'),
	'GRD'=>array('name'=>'Drachma','code'=>'300'),
	'DKK'=>array('name'=>'Danish Krone','code'=>'208'),
	'XCD'=>array('name'=>'East Caribbean Dollar','code'=>'951'),
	'FRF'=>array('name'=>'French Franc','code'=>'250'),	
	'GTQ'=>array('name'=>'Guatemalan Quetzal','code'=>'320'),
	'GNF'=>array('name'=>'Guinea Franc','code'=>'324'),
	'GWP'=>array('name'=>'Guinea-Bissau Peso','code'=>'624'),	
	'GYD'=>array('name'=>'Guyana Dollar','code'=>'328'),
	'HTG'=>array('name'=>'Haiti Gourde','code'=>'332'),		
	'ITL'=>array('name'=>'Italian Lira','code'=>'380'),
	'HNL'=>array('name'=>'Honduran Lempira','code'=>'340'),
	'HUF'=>array('name'=>'Forint','code'=>'348'),
	'ISK'=>array('name'=>'Iceland Krona','code'=>'352'),	
	'IDR'=>array('name'=>'Indonesian Rupiah','code'=>'360'),
	'XDR'=>array('name'=>'SDR','code'=>'960'),
	'IRR'=>array('name'=>'Iranian Rial','code'=>'364'),
	'IQD'=>array('name'=>'Iraqi Dinar','code'=>'368'),
	'IEP'=>array('name'=>'Irish Pound','code'=>'372'),
	'ILS'=>array('name'=>'New Israeli Sheqel','code'=>'376'),
	'ITL'=>array('name'=>'Italian Lira','code'=>'380'),
	'JMD'=>array('name'=>'Jamaican Dollar','code'=>'388'),
	'JPY'=>array('name'=>'Yen','code'=>'392'),
	'JOD'=>array('name'=>'Jordanian Dinar','code'=>'400'),
	'KZT'=>array('name'=>'Kazakhstan Tenge','code'=>'398'),
	'KES'=>array('name'=>'Kenyan Shilling','code'=>'404'),	
	'KPW'=>array('name'=>'North Korean Won','code'=>'408'),
	'KRW'=>array('name'=>'South Korean Won','code'=>'410'),
	'KWD'=>array('name'=>'Kuwaiti Dinar','code'=>'414'),
	'KGS'=>array('name'=>'Kyrgyzstan Som','code'=>'417'),
	'LAK'=>array('name'=>'Laos Kip','code'=>'418'),
	'LVL'=>array('name'=>'Latvian Lats','code'=>'428'),
	'LBP'=>array('name'=>'Lebanese Pound','code'=>'422'),
	'ZAR'=>array('name'=>'Rand','code'=>'710'),
	'LSL'=>array('name'=>'Loti','code'=>'426'),
	'LRD'=>array('name'=>'Liberian Dollar','code'=>'430'),
	'LYD'=>array('name'=>'Libyan Dinar','code'=>'434'),
	'CHF'=>array('name'=>'Swiss Franc','code'=>'756'),
	'LTL'=>array('name'=>'Lithuanian Litas','code'=>'440'),
	'LUF'=>array('name'=>'Luxembourg Franc','code'=>'442'),
	'MKD'=>array('name'=>'Macedonian Denar','code'=>'807'),
	'MGF'=>array('name'=>'Malagasy Franc','code'=>'450'),
	'MWK'=>array('name'=>'Kwacha','code'=>'454'),
	'MYR'=>array('name'=>'Malaysian Ringgit','code'=>'458'),
	'MVR'=>array('name'=>'Maldives Rufiyaa','code'=>'462'),	
	'MTL'=>array('name'=>'Maltese Lira','code'=>'470'),	
	'FRF'=>array('name'=>'French Franc','code'=>'250'),
	'MRO'=>array('name'=>'Mauritanian Ouguiya','code'=>'478'),
	'MUR'=>array('name'=>'Mauritius Rupee','code'=>'480'),
	'MXN'=>array('name'=>'Mexican Peso','code'=>'484'),
	'MXV'=>array('name'=>'Mexican Unidad de Inversion (UDI)','code'=>'979'),	
	'MDL'=>array('name'=>'Moldovan Leu','code'=>'498'),
	'FRF'=>array('name'=>'French Franc','code'=>'250'),
	'MNT'=>array('name'=>'Mongolian Tugrik','code'=>'496'),
	'XCD'=>array('name'=>'East Caribbean Dollar','code'=>'951'),
	'MAD'=>array('name'=>'Moroccan Dirham','code'=>'504'),
	'MZM'=>array('name'=>'Mozambique Metical','code'=>'508'),
	'MMK'=>array('name'=>'Myanmar Kyat','code'=>'104'),
	'ZAR'=>array('name'=>'Rand','code'=>'710'),
	'NAD'=>array('name'=>'Namibia Dollar','code'=>'516'),	
	'NPR'=>array('name'=>'Nepalese Rupee','code'=>'524'),
	'ANG'=>array('name'=>'Netherlands Antillian Guilder','code'=>'532'),
	'NLG'=>array('name'=>'Netherlands Gulder','code'=>'528'),
	'XPF'=>array('name'=>'CFP Franc','code'=>'953'),
	'NZD'=>array('name'=>'New Zealand Dollar','code'=>'554'),
	'NIO'=>array('name'=>'Nicaraguan Cordoba Oro','code'=>'558'),	
	'NGN'=>array('name'=>'Nigerian Naira','code'=>'566'),
	'NZD'=>array('name'=>'New Zealand Dollar','code'=>'554'),	
	'NOK'=>array('name'=>'Norwegian Krone','code'=>'578'),
	'OMR'=>array('name'=>'Rial Omani','code'=>'512'),
	'PKR'=>array('name'=>'Pakistan Rupee','code'=>'586'),	
	'PAB'=>array('name'=>'Balboa','code'=>'590'),
	'PGK'=>array('name'=>'Papua New Guinea Kina','code'=>'598'),
	'PYG'=>array('name'=>'Paraguay Guarani','code'=>'600'),
	'PEN'=>array('name'=>'Peru Nuevo Sol','code'=>'604'),
	'PHP'=>array('name'=>'Philippine Peso','code'=>'608'),
	'NZD'=>array('name'=>'New Zealand Dollar','code'=>'554'),
	'PLN'=>array('name'=>'Poland Zloty','code'=>'985'),
	'PTE'=>array('name'=>'Portuguese Escudo','code'=>'620'),
	'USD'=>array('name'=>'US Dollar','code'=>'840'),
	'QAR'=>array('name'=>'Qatari Rial','code'=>'634'),
	'FRF'=>array('name'=>'French Franc','code'=>'250'),
	'RON'=>array('name'=>'Romanian Leu','code'=>'642'),
	'RUR'=>array('name'=>'Russian Ruble','code'=>'810'),
	'RUB'=>array('name'=>'Russian Ruble','code'=>'643'),
	'RWF'=>array('name'=>'Rwanda Franc','code'=>'646'),
	'XCD'=>array('name'=>'East Caribbean Dollar','code'=>'951'),
	'FRF'=>array('name'=>'East Caribbean Dollar','code'=>'951'),
	'XCD'=>array('name'=>'French Franc','code'=>'250'),
	'XCD'=>array('name'=>'East Caribbean Dollar','code'=>'951'),
	'SHP'=>array('name'=>'St. Helena Pound','code'=>'654'),
	'WST'=>array('name'=>'Tala','code'=>'882'),
	'ITL'=>array('name'=>'Italian Lira','code'=>'380'),
	'STD'=>array('name'=>'Sao Tome and Principe Dobra','code'=>'678'),
	'SAR'=>array('name'=>'Saudi Riyal','code'=>'682'),	
	'SCR'=>array('name'=>'Seychelles Rupee','code'=>'690'),
	'SLL'=>array('name'=>'Sierra Leone Leone','code'=>'694'),
	'SGD'=>array('name'=>'Singapore Dollar','code'=>'702'),
	'SKK'=>array('name'=>'Slovak Koruna','code'=>'703'),
	'SIT'=>array('name'=>'Slovenia Tolar','code'=>'705'),
	'SBD'=>array('name'=>'Solomon Islands Dollar','code'=>'90'),
	'SOS'=>array('name'=>'Somalia Shilling','code'=>'706'),
	'ZAR'=>array('name'=>'South African Rand','code'=>'710'),
	'ESP'=>array('name'=>'Spanish Peseta','code'=>'724'),
	'LKR'=>array('name'=>'Sri Lanka Rupee','code'=>'144'),
	'SDP'=>array('name'=>'Sudanese Dinar','code'=>'736'),
	'SRG'=>array('name'=>'Suriname Guilder','code'=>'740'),
	'NOK'=>array('name'=>'Norwegian Krone','code'=>'578'),
	'SZL'=>array('name'=>'Swaziland Lilangeni','code'=>'748'),
	'SEK'=>array('name'=>'Swedish Krona','code'=>'752'),
	'CHF'=>array('name'=>'Swiss Franc','code'=>'756'),
	'SYP'=>array('name'=>'Syrian Pound','code'=>'760'),
	'TWD'=>array('name'=>'New Taiwan Dollar','code'=>'901'),
	'TJR'=>array('name'=>'Tajik Ruble','code'=>'762'),
	'TZS'=>array('name'=>'Tanzanian Shilling','code'=>'834'),
	'THB'=>array('name'=>'Thai Baht','code'=>'764'),	
	'NZD'=>array('name'=>'New Zealand Dollar','code'=>'554'),
	'TOP'=>array('name'=>'Tonga Paanga','code'=>'776'),
	'TTD'=>array('name'=>'Trinidad and Tobago Dollar','code'=>'780'),
	'TND'=>array('name'=>'Tunisian Dinar','code'=>'788'),
	'TRL'=>array('name'=>'Turkish Lira','code'=>'792'),
	'TMM'=>array('name'=>'Manat','code'=>'795'),		
	'UGX'=>array('name'=>'Ugandan Shilling','code'=>'800'),
	'UAH'=>array('name'=>'Hryvnia','code'=>'980'),
	'AED'=>array('name'=>'UAE Dirham','code'=>'784'),
	'GBP'=>array('name'=>'Pound Sterling','code'=>'826'),
	'UYU'=>array('name'=>'Peso Uruguayo','code'=>'858'),
	'UZS'=>array('name'=>'Uzbekistan Sum','code'=>'860'),
	'VUV'=>array('name'=>'Vanuatu Vatu','code'=>'548'),
	'VEB'=>array('name'=>'Venezuela Bolivar','code'=>'862'),
	'VND'=>array('name'=>'Viet Nam Dong','code'=>'704'),	
	'XPF'=>array('name'=>'CFP Franc','code'=>'953'),
	'MAD'=>array('name'=>'Moroccan Dirham','code'=>'504'),
	'YER'=>array('name'=>'Yemeni Rial','code'=>'886'),
	'YUN'=>array('name'=>'Yugoslavian Dinar','code'=>'891'),
	'ZRN'=>array('name'=>'Unknown','code'=>'180'),
	'ZMK'=>array('name'=>'Zambia Kwacha','code'=>'894'),
	'ZWD'=>array('name'=>'Zimbabwe Dollar','code'=>'716')	
	);
  } //end of class
	 	
   	

  /**
   * Add the Gateway to WooCommerce
   **/
  function woocommerce_add_neogate_gateway($methods) {
    $methods[] = 'WC_Neogate';
    return $methods;
  }

  add_filter('woocommerce_payment_gateways', 'woocommerce_add_neogate_gateway' );
  
}


?>
