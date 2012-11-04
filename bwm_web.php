<?php
////////////////////////////////////////////////////////////
// Braden's Custom website functions                      //
// Copyright 2009-2010 Braden W. MacDonald, bradenm.com   //
// Some rights reserved: leave this notice intact         //
// but otherwise use as you wish                          //
////////////////////////////////////////////////////////////
// Version 2.67

///// Basic functions //////

function _post($v) { // clean Post - returns a useable $_POST variable or NULL if and only if it is not set
  return isset($_POST[$v]) ? bwm_clean($_POST[$v]) : NULL;
}

function _postn($v) { // clean Post - returns a useable $_POST variable or NULL if the var is either only whitespace ("", " ", etc.) or not set
  $r = isset($_POST[$v]) ? bwm_clean($_POST[$v]) : '';
  return  $r == '' ? NULL : $r;
}

function _get($v) { // clean Get - returns a useable $_GET variable
  return isset($_GET[$v]) ? bwm_clean($_GET[$v]) : NULL;
}
function _getn($v) { // clean Get - returns a useable $_GET variable or NULL if the var is either only whitespace ("", " ", etc.) or not set
  $r = isset($_GET[$v]) ? bwm_clean($_GET[$v]) : '';
  return  $r == '' ? NULL : $r;
}
function _pog($v) { // clean Post Or Get - returns a useable request variable
  return isset($_POST[$v]) ? bwm_clean($_POST[$v]) : (isset($_GET[$v]) ? bwm_clean($_GET[$v]) : NULL);
}

function etrim($str, $max_length = 35) { // Ensure $str is no longer than $max_length, shortening and adding an ellipsis as needed
	return strlen($str) > $max_length ? rtrim(substr($str,0,$max_length-1)).'&hellip;' : $str;
}

function print_array($a) {
	print('<pre>'); print_r($a); print('</pre><br />');
}

function _eor() { // Either or - returns first non-empty argument
	foreach(func_get_args() as $a) { if (!empty($a)) return $a; }
	return null;
}

///// Misc functions //////

function bwm_filesize_str($file_or_size, $nonexistent_return = 'temporarily unavailable'){ 
        $b = 0;//Number of bytes
        if (is_string($file_or_size)) {
        	if (!file_exists($file_or_size))
        		return $nonexistent_return; 
        	$b = (int)filesize($file_or_size);
		} else {
			$b = intval($file_or_size);
		} 
        $s = array('B', 'kB', 'MB', 'GB', 'TB'); 
        $con = 1024; 
        $e = (int)(log($b,$con)); 
        return number_format($b/pow($con,$e), $e > 0 ? 1 : 0).' '.$s[$e]; 
}

function bwm_clean($s) { // Strip Slashes if needed. 
  if (get_magic_quotes_gpc())
    return trim(stripslashes($s));
  return trim($s);
}

// Standard HMAC algorithm to securely combine two strings and then cryptographically hash them
function bwm_hmac($key, $data, $hash = 'md5', $blocksize = 64) {
  if (strlen($key)>$blocksize) {
    $key = pack('H*', $hash($key));
  }
  $key  = str_pad($key, $blocksize, chr(0));
  $ipad = str_repeat(chr(0x36), $blocksize);
  $opad = str_repeat(chr(0x5c), $blocksize);
  return $hash(($key^$opad) . pack('H*', $hash(($key^$ipad) . $data)));
}

// Validate an email address, properly (from http://www.linuxjournal.com/article/9585):
function bwm_validate_email($email) {
	$isValid = true;
	$atIndex = strrpos($email, "@");
	if (is_bool($atIndex) && !$atIndex) {
	  $isValid = false;
	} else {
    $domain = substr($email, $atIndex+1);
    $local = substr($email, 0, $atIndex);
    $localLen = strlen($local);
    $domainLen = strlen($domain);
    if ($localLen < 1 || $localLen > 64) {
      // local part length exceeded
      $isValid = false;
    } else if ($domainLen < 1 || $domainLen > 255) {
      // domain part length exceeded
      $isValid = false;
    } else if ($local[0] == '.' || $local[$localLen-1] == '.') {
      // local part starts or ends with '.'
      $isValid = false;
    } else if (preg_match('/\\.\\./', $local)) {
      // local part has two consecutive dots
      $isValid = false;
    } else if (!preg_match('/^[A-Za-z0-9\\-\\.]+$/', $domain)) {
      // character not valid in domain part
      $isValid = false;
    } else if (preg_match('/\\.\\./', $domain)) {
      // domain part has two consecutive dots
      $isValid = false;
    } else if (!preg_match('/^(\\\\.|[A-Za-z0-9!#%&`_=\\/$\'*+?^{}|~.-])+$/', str_replace("\\\\","",$local))) {
      // character not valid in local part unless 
      // local part is quoted
      if (!preg_match('/^"(\\\\"|[^"])+"$/', str_replace("\\\\","",$local))) {
        $isValid = false;
      }
    }
    if ($isValid && function_exists('checkdnsrr') && !(checkdnsrr($domain,"MX") || checkdnsrr($domain,"A"))) {
      // domain not found in DNS
      $isValid = false;
    }
	}
	return $isValid;
}

///// Database handling //////

Class BWMDatabase {
  private $conn;
  private $ready = false;
  private $db_name;
  
  function __construct($ip, $db, $user, $pass) {
    $this->conn = @mysql_connect($ip, $user, $pass);
    if ($this->conn === false || !mysql_select_db($db, $this->conn)) {
      $this->ready = false;
      return;
    }
    mysql_query("SET NAMES 'utf8'", $this->conn);
    $this->ready = true;
    $this->db_name = $db;
  }
  function ready () {
    return $this->ready;
  }
  
  public static function parse_args($sql, array $args) {
    // Pass SQL with %d and %s in the SQL. These will be replaced with the values of $args (which will become escaped)
    // Pass %n in $sql to be converted to NULL if its arg is null or "%s" if its arg is not null
    // Pass %i in $sql to be converted to NULL if its arg is null or %d if its arg is not null
    // Pass %l (lowercase L) in $sql to have an array (bob, joe, fred) converted to: "bob","joe","fred"
    // Pass %T in $sql to have a unix timestamp converted to MySQL Datetime format or NULL
    // Pass %t in $sql to have a unix timestamp converted to MySQL Datetime format
    if (count($args) > 0) { // We have to clean things up with sprintf
  		$args_clean = array();
  		$last_pos = -2; // last pos where a % sign was found (needed of special handling of %n)
  		foreach($args as $a) {
  			do {
  				$last_pos = strpos($sql, '%', $last_pos+2);
  			} while ($last_pos !== FALSE && $sql{$last_pos+1} == '%');
  			if ($sql{$last_pos+1} == 'n') { // Format for this arg is special %n type (NULL or unquoted string)
  				if ($a === NULL)
  					$args_clean[] = 'NULL';
  				else
  					$args_clean[] = (is_string($a) || is_object($a) || is_array($a)) ? '"'.mysql_real_escape_string($a).'"' : $a;
  				$sql{$last_pos+1} = 's';
  			} else if ($sql{$last_pos+1} == 'i') { // Format for this arg is special %i type (NULL or integer)
  				if ($a === NULL)
  					$args_clean[] = 'NULL';
  				else
  					$args_clean[] = intval($a);
  				$sql{$last_pos+1} = 's';
  			} else if ($sql{$last_pos+1} == 'T') { // Format for this arg is special %T type (NULL or timestamp)
  				if ($a === NULL)
  					$args_clean[] = 'NULL';
  				else
  					$args_clean[] = '"'.date("Y-m-d H:i:s", intval($a)).'"';
  				$sql{$last_pos+1} = 's';
  			} else if ($sql{$last_pos+1} == 't') { // Format for this arg is special %t type (NULL or timestamp)
  					$args_clean[] = '"'.date("Y-m-d H:i:s", intval($a)).'"';
  				$sql{$last_pos+1} = 's';
  			} else if ($sql{$last_pos+1} == 'l') { // Format for this arg is special %l type (list of quoted strings)
  				$a2 = array();
  				foreach ($a as $a_individual) {
            $a2[] = '"'.mysql_real_escape_string($a_individual).'"';
          }
  				$args_clean[] = implode(',', $a2);
  				$sql{$last_pos+1} = 's';
  			} else 
  				$args_clean[] = (is_string($a) || is_object($a) || is_array($a)) ? mysql_real_escape_string($a) : $a;
  		}
  		$sql = vsprintf($sql, $args_clean);
  	}
  	return $sql;
  }

  function run($sql /* pass args here, optional */ ) {
  	if (!$this->ready) { return false; }
  	if (func_num_args() > 1) {
  		$args = func_get_args();
  		unset($args[0]);
  		$sql = self::parse_args($sql, $args);
  	}
  	$res = mysql_query($sql, $this->conn);
  	if ($res === TRUE && strtoupper(substr($sql,0,6)) == 'INSERT')
  		return mysql_insert_id($this->conn);
  	if ($res === FALSE || $res === TRUE)
  		return $res;
  	$list = array();
  	while ($row = mysql_fetch_assoc($res)) {
  		$list[] = $row;
  	}
  	return $list;
  }
  
  function debug($sql /* pass args here, optional */ ) {
  	if (!$this->ready) {
  		echo('<strong>Error: </strong> Unable to establish connection to database server.</strong>');
  		return false;
  	}
  	if (func_num_args() > 1) { // We have to clean things up with sprintf
  		$args = func_get_args();
  		unset($args[0]);
  		$sql = self::parse_args($sql, $args);
  	}
  	echo 'Running "'.htmlspecialchars($sql).'": ';
  	$res = mysql_query($sql, $this->conn);
  	if ($res === TRUE && strtoupper(substr($sql,0,6)) == 'INSERT') {
  		echo '<strong>Inserted</strong>, new ID '.mysql_insert_id($this->conn).'<br/>';
  		return mysql_insert_id($this->conn);
  	}
  	if ($res === TRUE) {
  		echo '<strong>Success</strong><br/>';
  		return $res;
  	}
  	if ($res === FALSE) {
  		echo '<strong style="color: red;">Failed:</strong> '.mysql_error($this->conn).'<br/>';
  		return $res;
  	}
  	$list = array();
  	while ($row = mysql_fetch_assoc($res)) {
  		$list[] = $row;
  	}
  	echo '<br/><pre>';
  	print_r($list); echo '</pre><br/>';
  	return $list;
  }
  function pretend($sql /* pass args here, optional */) {
    // This function will never run any queries on the database, but otherwise accepts arguments like the above ones.
		$args = func_get_args();
		unset($args[0]);
		$sql = self::parse_args($sql, $args);
  	echo 'Would run "'.htmlspecialchars($sql).'": ';
  	return true;
  }
  
  ///// Helper functions
  function last_error() {
    return $this->ready ? mysql_error($this->conn) : 'Unable to connect to database.';
  }
  function get_enum_values($table, $column) {
    $values = $this->run('SHOW COLUMNS FROM `'.$table.'` LIKE "'.$column.'"');
    $values = isset($values[0]['Type']) ? $values[0]['Type'] : "enum('error')";
    return explode("','", substr($values, 6, -2));
  }
  function get_set_values($table, $column) {
    $values = $this->run('SHOW COLUMNS FROM `'.$table.'` LIKE "'.$column.'"');
    $values = isset($values[0]['Type']) ? $values[0]['Type'] : "set('error')";
    return explode("','", substr($values, 5, -2));
  }
  /**
   * Insert or update a row into a table. 
   * Example:
   * insert_or_update('users', 'uid', $user->id,
   *                  'name', '%n', $user->name,
   *                  'last_access', 'NOW()', NULL);
   */
  function insert_or_update($table, $idcol, $idnum = NULL /*, trios of column,template(%d,%i,%n,%s),substitute can follow here*/) {
  	$num_args = func_num_args()-3;
  	if ($num_args % 3 != 0)
  		throw new Exception('Number of arguments to insert_or_update must be a multiple of three.');
  	if ($num_args < 3)
  		throw new Exception('Must pass at least one column name,type,value trio to insert_or_update');
  	$set_str = '';
  	$set_args = array();
  	$update_str = '';
  	for ($i = 0; $i < $num_args; $i += 3) {
  		$key = func_get_arg(3+$i);
  		$template = func_get_arg(3+$i+1);
  		$value = func_get_arg(3+$i+2);
  		
  		if ($template == '%s')
  			throw new Exception('Dangerous template %s is not allowed. Use %n or "%s" (in quotes).');
  		
  		$set_str .= ($i == 0 ? '':', ')."`$key`=$template ";
  		$update_str .= ($i == 0 ? '':', ')."`$key`=VALUES(`$key`)"; // for ON DUPLICATE KEY UPDATE
  		$n_count = substr_count($template, '%');
  		if ($n_count == 1)
  			$set_args[] = $value;
  		else if ($n_count > 1 || $value !== NULL)
  			throw new Exception('Invalid use of % or data passed unexpectedly for colum "'.$key.'"');
  	}
  	$set_str = self::parse_args($set_str, $set_args);
  	if ($idnum)
  		return $this->run('INSERT INTO `'.$table.'` SET `'.$idcol.'`=%d, '.$set_str.' ON DUPLICATE KEY UPDATE '.$update_str, $idnum);
  	else
  		return $this->run('INSERT INTO `'.$table.'` SET '.$set_str);
  }
/**
   * Update a row into a table. 
   * Example:
   * update('users', 'uid', $user->id,
   *        'name', '%n', $user->name,
   *        'last_access', 'NOW()', NULL);
   */
  function update($table, $idcol, $idnum/*, trios of column,template(%d,%i,%n,%s),substitute can follow here*/) {
  	$num_args = func_num_args()-3;
  	if ($num_args % 3 != 0)
  		throw new Exception('Number of arguments to insert_or_update must be a multiple of three.');
  	if ($num_args < 3)
  		throw new Exception('Must pass at least one column name,type,value trio to insert_or_update');
  	$set_str = '';
  	$set_args = array();
  	for ($i = 0; $i < $num_args; $i += 3) {
  		$key = func_get_arg(3+$i);
  		$template = func_get_arg(3+$i+1);
  		$value = func_get_arg(3+$i+2);
  		
  		if ($template == '%s')
  			throw new Exception('Dangerous template %s is not allowed. Use %n or "%s" (in quotes).');
  		
  		$set_str .= ($i == 0 ? '':', ')."`$key`=$template ";
  		$n_count = substr_count($template, '%');
  		if ($n_count == 1)
  			$set_args[] = $value;
  		else if ($n_count > 1 || $value !== NULL)
  			throw new Exception('Invalid use of % or data passed unexpectedly for colum "'.$key.'"');
  	}
  	$set_str = "UPDATE `$table` SET $set_str WHERE `$idcol`=%d";
  	$set_args[] = $idnum;
  	$set_str = self::parse_args($set_str, $set_args);
  	return $this->run($set_str);
  }
  
  
  
  function print_edit_form($table, $id = NULL, array $want_columns = null) {
  	$columns = $this->run('SHOW FULL COLUMNS FROM `'.$table.'`');
  	$pri_key = ''; // name of the primary key. Automatically detected
  	$values = array();
  	if (!isset($columns[0]))
  		throw new Exception('Unable to find columns for table "'.$table.'".');

  	// Identify the primary key and load default values:
  	foreach($columns as $col) {
  		if ($col['Key'] == 'PRI')
  			$pri_key = $col['Field'];
  		if (!$id) {
  			// If creating a new entry, use default values:
  			$default = $col['Default']; 
  			if ($default == '' || $default == 'NULL')
  				$default = NULL;
  			$values[$col['Field']] = $default;
  		}
  	}

  	// Load data from this current row if one exists:
  	if ($id) { 
  		if ($want_columns) { // We only need to process a subset of columns:
  			foreach($columns as $k=>$c) {
  				if (!in_array($c['Field'], $want_columns))
  					unset($columns[$k]); // We don't need to bother with this one.
  			}
  			$want_columns_str = '`'.implode('`,`', $want_columns).'`';
  		} else // we want all columns:
  			$want_columns_str = '*';
  		$data = $this->run('SELECT '.$want_columns_str.' FROM `'.$table.'` WHERE `'.$pri_key.'`=%d', $id);
  		if (!isset($data[0]))
  			throw new Exception('Unable to find entry with '.$pri_key.'='.intval($id).' in table "'.$table.'".');
  		foreach($data[0] as $k=>$v)
  			$values[$k] = $v;
  	}
  	
  	// Check for foreign keys
  	$fkeys_data = $this->run('SELECT ke.column_name, ke.referenced_table_name, ke.referenced_column_name FROM information_schema.KEY_COLUMN_USAGE ke WHERE ke.TABLE_SCHEMA = "'.$this->db_name.'" AND ke.table_name = "'.$table.'" AND referenced_column_name IS NOT NULL');
  	$fkeys = array();
  	if (isset($fkeys_data[0])) { // Yes, there is at least one column with a foreign key
  		$table_indices = $this->run('SHOW INDEX FROM `'.$table.'`');
  		foreach ($fkeys_data as $fkey) {
  			$col = $fkey['column_name']; // the column in this table which has a foreign key
  			if ($want_columns && !in_array($col, $want_columns))
  				continue; // Skip this one, as we are ignoring that column
  			$ref_table = $fkey['referenced_table_name'];
  			$ref_col = $fkey['referenced_column_name'];
  			
  			// If the index for this column has a comment like (friendly_ref:table.col_name), load the col_name column from the foreign table as well as the key column
  			$friendly_fkey_field = null;
  			foreach($columns as $col_info) {
  				if ($col_info['Field'] == $col && $col_info['Comment']) {
  					$comment = $col_info['Comment'];
  					$lpos = strpos($comment, '(friendly_ref:');
	  				$rpos = strpos($comment, ')');
	  				if ($lpos !== FALSE && $rpos > $lpos) {
	  					$friendly_fkey_field = substr($comment, $lpos+14, $rpos-$lpos-14);
	  					if (substr($friendly_fkey_field,0,strlen($ref_table)+1) != "$ref_table.")
	  						throw new Exception('Inalid (friendly_ref:...) setting. ... must be "'.$ref_table.'.col_name"');
	  					$friendly_fkey_field = substr($friendly_fkey_field,strlen($ref_table)+1);
	  				} 
  				}
  			}
  			
  			$fkeys[$col] = array();
  			if ($friendly_fkey_field)
  				$options = $this->run("SELECT `$ref_col`,`$friendly_fkey_field` FROM `$ref_table` WHERE 1 LIMIT 0,9999");
  			else
  				$options = $this->run("SELECT `$ref_col` FROM `$ref_table` WHERE 1 LIMIT 0,9999");
  			if (!isset($options[0]))
  				continue; // Error, or there seem to be no options
  			foreach($options as $option) {
  				if ($friendly_fkey_field)
  					$fkeys[$col][$option[$ref_col]] = $option[$ref_col].': '.$option[$friendly_fkey_field];
  				else
  					$fkeys[$col][$option[$ref_col]] = $option[$ref_col];
  			}
  		}
  	}
  	
  	echo ('<table>');
  	foreach($columns as $col) {
  		if ($want_columns && !in_array($col['Field'], $want_columns))
  			continue;
  		$field = $col['Field'];
  		$type = $col['Type'];
  		$val = $values[$field];
  		$null_ok = $col['Null'] == 'YES';
  		
  		$length = null; // n/a
  		$bpos = strpos($col['Type'], '(');
  		$rbpos = strpos($col['Type'], ')');
  		$unsigned = false;
  		if ($bpos !== false) { // The type contains length information
  			$length = intval(substr($type, $bpos+1, $rbpos-$bpos-1));
  			$type = substr($type,0,$bpos);
  		}
  		
  		if (substr($col['Type'],-8) == 'unsigned')
  			$unsigned = true;
  		echo '<tr><td valign="top">'.$field.'</td><td>';
		if (isset($fkeys[$field])) { // A field with a foreign key
			echo '<select name="'.$field.'">';
			$options = array();
			if ($null_ok)
				echo '<option value="">Not set</option>';
			foreach($fkeys[$field] as $id => $friendly) {
				echo '<option value="'.$id.'"'.($val == $id ? ' selected=1' : '').'>'.$friendly.'</option>';
			} 
			echo '</select>';
  		} else if (substr($type, -4) == 'char') { // string type (char, varchar)
			echo '<input type="text" name="'.$field.'" value="'.htmlspecialchars($val).'" maxlength="'.$length.'" />';
		} else if (substr($type, -3) == 'int') { // numeric type (int, tinyint, etc.)
			static $bytes_itypes = array('int' => 4, 'tinyint' => 1, 'smallint' => 2, 'mediumint' => 3, 'bigint' => 8);
			$max = $unsigned? pow(2,$bytes_itypes[$type]*8)-1 : pow(2, $bytes_itypes[$type]*8-1)-1;
			$min = $unsigned? 0 : 0-pow(2,$bytes_itypes[$type]*8-1);
			if ($unsigned)
				$js = 'this.value = this.value.replace(/[^\d]/g, \'\');';
			else
				$js = 'this.value = this.value.replace(/[^\d\-]/g, \'\').replace(/^(\-?\d+).*$/, \'$1\');';
			if (!$null_ok)
				$js .= ' if (this.value == \'\') { this.value=0; } ';
			$js .= 'if (parseInt(this.value) < '.$min.') { this.value='.$min.'; } ';
			$js .= 'else if (parseInt(this.value) > '.$max.') { this.value='.$max.'; } ';
			echo '<input type="text" name="'.$field.'" value="'.$val.'"'.($length ?  ' maxlength="'.$length.'"' : '').' onchange="'.$js.'" />';
			// Above, $length refers to the optional integer type "display width", which we'll interpret as a character 
		} else if ($type == 'date') {
			echo '<input type="text" name="'.$field.'" value="'.$val.'" maxlength="10" onchange="this.value=this.value.replace(/(\d\d\d\d)-?[^\-]*$/, \'$1-01-01\'); if (this.value.search(/^\d\d\d\d\-\d\d\-\d\d$/) == -1) { this.value=\''.($null_ok ? '' : ' 2000-01-01').'\'; }" />';
			// Above, $length refers to the optional integer type "display width", which we'll interpret as a character 
		} else if ($type == 'enum') {
			echo '<select name="'.$field.'">';
			$options = array();
			if ($null_ok)
				echo '<option value="">Not set</option>';
			foreach(explode("','", substr($col['Type'], 6, -2)) as $option) {
				echo '<option value="'.$option.'"'.($val == $option ? ' selected=1' : '').'>'.$option.'</option>';
			} 
			echo '</select>';
		} else if (substr($type, -4) == 'text') {
			echo '<textarea name="'.$field.'" style="width: 600px; height: 350px;">'.htmlspecialchars($val).'</textarea>';
		} else {
			echo '('.htmlspecialchars($val).')';
		}
  	}
    echo '</table>';
  }
}

Class BWMJournalledDatabase extends BWMDatabase {
	protected $journal, $db_name, $ignored_tables;
	protected static $ignored_ops = array('SELECT', 'SHOW', 'DESCRIBE', 'HELP', 'EXPLAIN');
	protected static $journalled_ops = array('INSERT', 'UPDATE', 'DELETE', 'REPLACE', 'CREATE', 'ALTER');
	function __construct($ip, $db, $user, $pass, $journal_db) {
		$this->journal = $journal_db;
		$this->db_name = $db;
		parent::__construct($ip, $db, $user, $pass);
	}
	public function journal($sql, $result = NULL) {
		$op = strtoupper(substr(ltrim($sql),0,strpos($sql, ' ')));
		if (in_array($op, self::$ignored_ops))
			return false; // Don't journal unless the database has changed.
		// Check if we should ignore this operation:
		$tables_modified = self::detect_tables($sql);
		$ignored_count = 0;
		foreach ($tables_modified as $table) {
			if (isset($this->ignored_tables[$table]))
				$ignored_count++;
		}
		if ($ignored_count == count($tables_modified))
			return false; // All the tables modified are on the ignore list, so don't journal this operation
		// Okay, journal:
		if ($op == 'INSERT' && $result && is_int($result)) // It was an insert and we know the resulting insert ID, so record it
			$r = $this->journal->run('INSERT INTO `%s` SET `sql`="%s", insert_id=%d', $this->db_name, $sql, $result);
		else // Other type of operation or unknown insert ID:
			$r = $this->journal->run('INSERT INTO `%s` SET `sql`="%s"', $this->db_name, $sql);
		if ($r === false)
			throw new Exception('Unable to journal SQL statement.');
		return true;
	}
	/**
	 * Determine if the given SQL is compatible with this journalled database object.
	 * Will reject operations like DO, USE, CALL, and HANDLER
	 * @param string $sql
	 * @return unknown_type
	 */
	protected static function can($sql) {
		$op = strtoupper(substr(ltrim($sql),0,strpos($sql, ' ')));
		return (in_array($op, self::$ignored_ops) || in_array($op, self::$journalled_ops));
	}
	/**
	 * Detect which tables will potentially be modified by the given SQL statement
	 * @param string $sql
	 * @return array array of the table names
	 */
	public static function detect_tables($sql) {
		$tables_modified = array();
		$sql = strtolower(trim($sql));
		$sql = preg_replace('/\s+/', ' ', $sql); // Normalize whitespace
		$op = substr($sql,0,strpos($sql, ' '));
		$matches = null;
		if ($op == 'insert') {
			preg_match('/^insert(?: low_priority| delayed| high_priority| ignore| into)* `?(\w+)`? /', $sql, $matches);
			if (!isset($matches[1]))
				throw new Exception('Unable to determine the table modified by SQL INSERT statement '.$sql);
			$tables_modified[] = $matches[1];
		} else if ($op == 'replace') {
			preg_match('/^replace(?: low_priority| delayed| into)* `?(\w+)`? /', $sql, $matches);
			if (!isset($matches[1]))
				throw new Exception('Unable to determine the table modified by SQL REPLACE statement '.$sql);
			$tables_modified[] = $matches[1];
		} else if ($op == 'update') { // Can affect multiple tables
			preg_match('/^update(?: low_priority| ignore)* ([\w`\, ]+) set /', $sql, $matches);
			if (!isset($matches[1]))
				throw new Exception('Unable to determine the table modified by SQL UPDATE statement '.$sql);
			$tables_modified = explode(',',$matches[1]);
			foreach ($tables_modified as $k => $v) {
				$tables_modified[$k] = trim($v, '` ');
			}
		} else if ($op == 'delete') { // Can affect multiple tables
			/* Delete can have one of three possible syntaxes: 
			 * 1. DELETE [LOW_PRIORITY] [QUICK] [IGNORE] FROM single_table_name [...]
			 * 2. DELETE [LOW_PRIORITY] [QUICK] [IGNORE] FROM table1[.*],[table2[.*]][,tableX[.*]...] USING ...
			 * 3. DELETE [LOW_PRIORITY] [QUICK] [IGNORE] table1[.*][,table2[.*]][,tableX[.*]] FROM
			 */
			// So, first get rid of the beginning they all have in common:
			$sql = preg_replace('/^delete(?: low_priority| quick| ignore)* /', '', $sql);
			if (substr($sql,0,4) == 'from') { // Case 1 or 2:
				if (preg_match('/^from (`?\w+`?(\.\*)?)( ?, ?(`?\w+`?(\.\*)?))* using /', $sql)) { // Case 2
					$table_list_str = substr($sql,5,strpos($sql, ' using ')-5);
					$tables_modified = explode(',',$table_list_str);
					foreach ($tables_modified as $k => $v) {
						$tables_modified[$k] = trim($v, '` .*');
					}
				} else { // Case 1
					$tables_modified[] = trim(substr($sql,5,strpos($sql, ' ',6)-5), '`');
				}
			} else { // Case 3:
				$from_pos = strpos($sql, ' from ');
				if ($from_pos === FALSE)
					throw new Exception('DELETE statement is missing the FROM keyword');
				$table_list_str = substr($sql,0,$from_pos);
				$tables_modified = explode(',',$table_list_str);
				foreach ($tables_modified as $k => $v) {
					$tables_modified[$k] = trim($v, '` .*');
				}
			}
		} else if ($op == 'create') {
			preg_match('/^create(?: temporary)? table(?: if not exists)? `?(\w+)`? /', $sql, $matches);
			if (!isset($matches[1]))
				throw new Exception('Unable to determine the table created by SQL CREATE statement '.$sql);
			$tables_modified[] = $matches[1];
		} else if ($op == 'alter') {
			preg_match('/^alter(?: online| offline| ignore)* table `?(\w+)`? /', $sql, $matches);
			if (!isset($matches[1]))
				throw new Exception('Unable to determine the table modified by SQL ALTER statement "'.$sql.'" Please note that only ALTER TABLE is currently supported.');
			$tables_modified[] = $matches[1];
		} else {
			throw new Exception('detect_tables only works with the designated journallable SQL statements.');
		}
		return $tables_modified;
	}
	/**
	 * Ignore all queries that reference this table (i.e. don't journal those changes)
	 * @param string $t The table to ignore
	 * @param bool $ignore Leave true to ignore the table, false to stop ignoring it
	 */
	public function ignore_table($t, $ignore = true) {
		if ($ignore)
			$this->ignored_tables[$t] = true;
		else if (isset($this->ignored_tables[$t]))
			unset($this->ignored_tables[$t]);
	} 
	/**
	 * Are we ignoring the given table?
	 * @param string $t the table name
	 * @return boolean
	 */
	public function is_table_ignored($t) {
		return isset($this->ignored_tables[$t]);
	} 
	function run($sql /* pass args here, optional */ ) {
		if (func_num_args() > 1) {
	  		$args = func_get_args();
	  		unset($args[0]);
	  		$sql = self::parse_args($sql, $args);
	  	}
	  	if (!self::can($sql))
	  		throw new Exception('Tried to run an SQL command not supported by the journalling database object.');
		$res = parent::run($sql);
		if ($res !== FALSE)
			$this->journal($sql, $res);
		return $res; 
	}
	function debug($sql /* pass args here, optional */ ) {
		if (func_num_args() > 1) {
	  		$args = func_get_args();
	  		unset($args[0]);
	  		$sql = self::parse_args($sql, $args);
	  	}
	  	if (!self::can($sql))
	  		throw new Exception('Tried to run an SQL command not supported by the journalling database object.');
		$res = parent::debug($sql);
		if ($res !== FALSE)
			$this->journal($sql, $res);
		return $res;
	}
	function pretend($sql /* pass args here, optional */ ) {
  		$args = func_get_args();
  		unset($args[0]);
  		$sql = self::parse_args($sql, $args);
	  	if (!self::can($sql))
	  		throw new Exception('Tried to run an SQL command not supported by the journalling database object.');
		return parent::pretend($sql);
	}
}

abstract class BWMDBObject {
	private $_custom_properties = array(); // Custom properties are added those by the script at run-time and never get stored in the database
	private $_frozen_properties = array(); // Used as a reference point to check for changes to any property
	protected $_templates = NULL; // Use optional. An array of templates (keys of this array are property names) e.g. "%d" - see BWMDatabase::parse_args
	protected $_id_column = NULL; // Use optional. Name of the ID column
	protected function __construct() {
		// Set $_templates for all properties to %n by default
    	foreach(get_object_vars($this) as $var => $val) {
    		if ($var{0} != '_' && !isset($this->_templates[$var]))
    			$this->_templates[$var] = '%n';
    	}
	}
	public function __set($name, $value) {
		if (isset($this->_custom_properties[$name]))
    		$this->_custom_properties[$name] = $value;
    	else
        	throw new Exception("Cannot write undefined property $name in class ".get_class($this).'.');
    }
    public function __get($name) {
    	if (isset($this->_custom_properties[$name]))
    		return $this->_custom_properties[$name];
    	throw new Exception("Cannot read undefined property $name in class ".get_class($this).'.');
    }
    protected function load_db_obj(array $obj) {
    	foreach($obj as $key => $val) {
    		$this->$key = $val;
    	}
    }
    public function watch_for_changes() {
    	foreach(get_object_vars($this) as $var => $val) {
    		if ($var{0} != '_')
    			$this->_frozen_properties[$var] = $val;
    	}
    }
    public function changed_properties() {
    	// Returns an array where the keys represent all changes properties and the values represent their OLD value
    	$changed = array();
    	foreach($this->_frozen_properties as $var => $val) {
    		if ($this->$var != $this->_frozen_properties[$var])// This property has changed:
    			$changed[$var] = $val;
    	}
    	return $changed;
    }
    public function save_changes_to(BWMDatabase $db_obj, $table, array $force_columns = NULL) {
    	$idc = $this->_id_column;
    	$is_updating = $this->$idc;
    	if (!$this->_templates || !$idc)
    		throw new Exception('The class must set $_templates and $_id_column in order to use save_changes_to()');
    	$sql = '';
    	if ($is_updating) { // We already have an id number, so we're updating
 			$changes = $this->changed_properties();
 			if ($force_columns) {
	 			foreach ($force_columns as $col) {
	 				if (!isset($changes[$col]))
	 					$changes[$col] = $this->$col; // Although the values of this array are ignored 
	 			}
 			}
 			if (count($changes) == 0)
    			return true; // No changes
    		$sql = 'UPDATE `'.$table.'` SET ';
    	} else { // We're inserting:
    		$changes = get_object_vars($this);
    		unset($changes[$idc]);
    		foreach($changes as $k => $v) {
    			if ($k{0} == '_')
    				unset($changes[$k]); // Remove settings like $_templates and computed/derived variables
    			if ($v == NULL && ($force_columns == NULL || !in_array($k, $force_columns)))
    				unset($changes[$k]);
    		} 
    		$sql = 'INSERT into `'.$table.'` SET ';
    	}
    	$values = array();
    	$first = true;
    	foreach ($changes as $col => $old_val) {
    		if (!isset($this->_templates[$col]))
    			throw new Exception("Template for '$col' is not defined!");
    		$sql .= ($first ? '' : ',').' `'.$col.'`='.$this->_templates[$col];
    		$values[] = $this->$col;
    		if ($first)
    			$first = false;
    	}
    	$sql = BWMDatabase::parse_args($sql, $values);
    	if ($is_updating)
    		$sql .= ' WHERE `'.$idc.'`='.$this->_frozen_properties[$idc];
    	$result = $db_obj->run($sql);
    	if (!$is_updating && $result)
    		$this->$idc = $result;
    	return $result;
    }
    public function add_custom_property($property_name, $value) {
    	if (isset($this->_custom_properties[$property_name]))
    		throw new Exception("Custom property \"$property_name\" already exists!");
    	$this->_custom_properties[$property_name] = $value;
    }
}
