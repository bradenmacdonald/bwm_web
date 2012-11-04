<?php
// Example usage of bwm_web.php. Public domain.
require_once(SHARED_PHP.'db.php'); // Declare a database, $g_db, to be used
require_once(SHARED_PHP.'geoip.php');

// Shared session/login info:
ini_set('session.use_only_cookies', 1);
session_name('sid');
session_set_cookie_params(2678400, '/', '.'.SITE_DOMAIN); // keep cookie for a month (session won't last that long b/c of garbage collection)
session_start();

/**
 * Example class for handling users 
 * Has features for email verification and persistent custom data storage
 * Also supports "guest" users with per-session data storage using the same interface 
 * Not recommended for use due to insecure password salt / hashing strategy
 * @author Braden Macdonald
 */
class ExampleUser extends BWMDBObject {
	public $email, $alt_login, $firstname, $lastname, $city, $provstate, $postalzip, $birthdate /* YYYY-MM-DD */, $lastlogin, $logincount;
	protected $uid, $password /* HMAC md5 */, $secret, $email_verified, $is_guest;
	/**
	 * An array of data, e.g.:
	 * Access with set_user_data() and get_user_data()
	 * Data values can be any data type, including arrays, and this class will serialize it  
	 * @var array
	 */
	protected $user_data;
	protected $user_data_loaded = false;

	const SALT = 'My SaLt'; // for passwords
	protected static $current_user;

	static function get($uid) {
		global $g_db;
		$r = $g_db->run('SELECT * FROM users WHERE uid=%d', $uid);
		if (!isset($r[0])) {
			return NULL;
		}
		return new ExampleUser($r[0]);
	}
	static function get_all($load_data = false) {
		global $g_db;
		$r = $g_db->run('SELECT * FROM users WHERE is_guest=0');
		if (!isset($r[0])) {
			return NULL;
		}
		$users = array();
		foreach ($r as $row) {
			$users[$row['uid']] = new ExampleUser($row);
		}
		if ($load_data) {
			$rows = $g_db->run('SELECT user_data.uid,user_data.data FROM user_data, users WHERE users.uid=user_data.uid AND users.is_guest=0');
			foreach ($rows as $row) {
				if ($row['data']) {
					$uid = $row['uid'];
					$users[$uid]->user_data = unserialize($row['data']);
					if (!is_array($users[$uid]->user_data))
						throw new Exception('Tried to load user_data but it wasn\'t an array');
					$users[$uid]->user_data_loaded = true;
				}
			}
			foreach ($users as $u) {
				if (!is_array($u->user_data)) {
					$users[$u->uid]->user_data = array();
					$users[$u->uid]->user_data_loaded = true;
				}
			}
		}
		return $users;
	}
	
	protected function __construct($db_row) {
		$this->load_db_obj($db_row);
	}
	/**
     * Load the user data
     * This function must be called before accessing $user_data
     */
	function load_user_data() {
		global $g_db;
		$data = $g_db->run('SELECT `data` FROM `user_data` WHERE `uid`=%d', $this->uid);
		if (isset($data[0]['data']) && $data[0]['data'] !== NULL)
			$d = unserialize($data[0]['data']);
		else
			$d = array();
		if (!is_array($d))
			throw new Exception('Tried to load user_data but it wasn\'t an array');
		$this->user_data = $d;
		$this->user_data_loaded = true;
	}

	function id() {
		return $this->uid;
	}
	function is_guest() {
		return $this->is_guest;
	}
	function convert_to_full_user() {
		$this->is_guest = false;
	}
	function name() {
		return $this->firstname.' '.$this->lastname;
	}
	function age() {
		if ($this->birthdate === NULL)
			return NULL; // No information available
		else
			return floor((time()-strtotime($this->birthdate))/31536000);
	}
	function email() {
		return $this->email;
	}
	function username() {
		return $this->alt_login;
	}
	function location() { // Location info for Google Maps or a similar service
		return $this->postalzip ? $this->postalzip : $this->city.', '.$this->provstate;
	}
	function email_verified() { // TODO: allow users to request verification
		return $this->email_verified;
	}
	function set_email_not_verified() {
		$this->email_verified = false;
	}
	function make_current_user() {
		session_regenerate_id();
		$_SESSION['user'] = $this->uid;
		self::$current_user = $this;
	}
	function is_current_user() {
		return $this->uid == $_SESSION['user'];
	}
	function check_password($password) {
		if (!$this->password)
			return false; // This user is disabled (or new, or is a guest) and has no password set.
		return ($this->password == bwm_hmac($password, self::SALT));
	}
	function get_user_data($key) {
		if (!$this->user_data_loaded)
			throw new Exception('Tried to read user data without loading it first.');
		return isset($this->user_data[$key]) ? $this->user_data[$key] : NULL;
	}
	function &modify_user_data($key, $data_type = "stdClass") { // Returns a reference to an object for storing user data
		if (!$this->user_data_loaded)
			throw new Exception('Tried to read user data without loading it first.');
		if(!isset($this->user_data[$key]))
			$this->user_data[$key] = new $data_type;
		else if (!is_object($this->user_data[$key]) || !($this->user_data[$key] instanceof $data_type))
			throw new Exception("Was expecting a $data_type object in user's $key store...");
		return $this->user_data[$key];
	}
	function set_user_data($key, $val) {
		if ($val !== NULL)
			$this->user_data[$key] = $val;
		else
			unset($this->user_data[$key]);
	}
	function read_user_data() {
		return $this->user_data; // Returns a copy of the whole user data array
	}
	/**
     * Save the user's profile (name, age, etc.)
     * Does NOT save user data.
     */
	function save($allow_create = true) {
		global $g_db;
		if ($allow_create && !$this->uid) {
			$new_uid = $g_db->run('INSERT INTO users SET firstname="New", lastname="User"');
			if ($new_uid === false)
				return false;
			$this->uid = $new_uid;
		}
		$r = $g_db->run('UPDATE users SET email=%n  ,   firstname="%s"  , lastname="%s"  , password=%n    , city=%n    , provstate=%n,    postalzip=%n ,    birthdate=%n    , lastlogin="%s"  , logincount=%d    , secret="%s"  , email_verified=%d          ,alt_login=%n    ,is_guest=%d  WHERE uid=%d',
		                               $this->email, $this->firstname, $this->lastname, $this->password, $this->city, $this->provstate,$this->postalzip, $this->birthdate, $this->lastlogin, $this->logincount, $this->secret, $this->email_verified ? 1:0,$this->alt_login,$this->is_guest, $this->uid);
		return $r !== false;
	}
	/**
     * Save the user data.
     * Does not save the profile (name, age, etc.)
     */
	function save_user_data() {
		global $g_db;
		if (!$this->user_data_loaded)
			throw new Exception('Tried to save user data that had not been loaded - could lead to loss of data, so aborted');
		//$g_db->run('REPLACE INTO `user_data` SET `uid`=%d,`data`=%n', $this->id, serialize($this->user_data));
		$g_db->insert_or_update('user_data', 'uid', $this->uid, 'data', '%n', serialize($this->user_data));
	}
	function set_password($new_password) {
		$this->password = bwm_hmac($new_password, self::SALT);
	}
	function new_secret() {
		$this->secret = substr(bwm_hmac(microtime(), 'randomHASH'), 0,10);
		return $this->secret;
	}
	/**
	 * Returns the user who is currently logged in, or NULL
	 * if $guest_ok is true, this function will create and return a guest user if no full user is logged in
	 */
	static function get_current_user($guest_ok = false) { 
		// Check for cached result:
		if (self::$current_user) {
			if (!$guest_ok && self::$current_user->is_guest)
				return NULL;
			return self::$current_user;
		}
		$r = self::get_current_user_db_row($guest_ok);
		if (!$r)
			return NULL;
		$u = new ExampleUser($r);
		$u->make_current_user();
		return $u;
	}
	static function blank_user() {
		return new ExampleUser(array());
	}
	static function user_exists($email) {
		global $g_db;
		$test = $g_db->run('SELECT firstname FROM users WHERE email="%s"', $email);
		return isset($test[0]);
	}
	static function username_exists($alt_login) {
		global $g_db;
		$test = $g_db->run('SELECT firstname FROM users WHERE alt_login="%s"', $alt_login);
		return isset($test[0]);
	}
	static function user_from_login($login, $password) {
		global $g_db;
		$info = $g_db->run('SELECT * FROM users WHERE email="%s" OR alt_login="%s"', $login, $login);
		if (!isset($info[0]))
			return NULL; // User does not exist
		$user = new ExampleUser($info[0]);
		if ($user->check_password($password))
			return $user;
		return NULL; // Wrong password
	}
	// Get a key that the user can provide (after getting it via email) to reset their password
	static function get_reset_key($email) {
		global $g_db;
		$info = $g_db->run('SELECT * FROM users WHERE email="%s"', $email);
		if (!isset($info[0]))
			return false; // User does not exist
		$user = new ExampleUser($info[0]);
		$user->new_secret();
		$user->save();
		return $user->secret;
	}
	// Reset the user's account. Returns new password on success, false on failure
	static function reset_password($email, $secret) {
		global $g_db;
		$info = $g_db->run('SELECT * FROM users WHERE email="%s" AND secret="%s"', $email, $secret);
		if (!$secret || !isset($info[0]))
			return false; // User does not exist or secret is wrong
		$user = new ExampleUser($info[0]);
		$new_password = 'eagle'.mt_rand(11,999);
		$user->set_password($new_password);
		$user->email_verified = true; // If they got the email, their address must be right
		$user->new_secret();
		$user->save();
		return $new_password;
	}
	static function require_login($url) {
		if (!self::get_current_user()) {
			header('Location: '.$url);
			exit();
		}
	}
	static function capitalize_last_name($name) {
	    $name = strtolower($name);
	    $name = join("'", array_map('ucwords', explode("'", $name)));
	    $name = join("-", array_map('ucwords', explode("-", $name)));
	    $name = join("Mac", array_map('ucwords', explode("Mac", $name)));
	    $name = join("Mc", array_map('ucwords', explode("Mc", $name)));
	    return $name;
	}
	
	static protected function get_current_user_db_row($guest_ok = false) { 
		global $g_db;
		// Check for a user based on the uid stored in the session info:
		if (isset($_SESSION['user']) && $_SESSION['user']) {
			$info = $g_db->run('SELECT * FROM users WHERE uid=%d', $_SESSION['user']);
			if (isset($info[0])) {
				$row = $info[0];
				if ($guest_ok || !$row['is_guest']) {
					return $info[0];
				}
			} else { // User no longer exists!
				$_SESSION['user'] = NULL;
			}
		}
		// No user - create a guest user account:
		if ($guest_ok) {
			$auto_city = GeoIP::city(); 
			$auto_provstate = GeoIP::region_code(); 
			$new_uid = $g_db->run('INSERT INTO users SET firstname="Guest", lastname="User", lastlogin=CURDATE(), logincount=1, city=%n, provstate=%n, is_guest=1', $auto_city, $auto_provstate);
			if (!$new_uid)
				throw new Exception('Unable to create guest user');
			$rows = $g_db->run('SELECT * FROM users WHERE uid=%d', $new_uid); // Load defaults for all other columns
			if (!isset($rows[0]))
				throw new Exception('Unable to SELECT just-created database entry.');
			return $rows[0];
		}
		return NULL;
	}
}