bwm_web
=======

Old PHP code I developed: Database wrapper, DB replication helper, a rudimentary
ORM, and utility methods

I don't use this anymore (since I've outgrown PHP for web development), but if
anyone finds it interesting or useful, help yourself.

Classes
-------

* __BWMDatabase__: Simple MySQL database wrapper with handy SQL formatting and
  debugging built in.
  - `run($sql[, args])`: Execute the SQL given, returning the results, if any.
    Supports the following format specifiers for passing arguments:
      + `%d`: decimal number
      + `%s`: string - will be automatically escaped.
      + `%n`: will be converted to `NULL` if its arg is null or `"%s"` not null
      + `%i`: converted to `NULL` if its arg is null or `%d` if its arg isn't null
      + `%l` (lowercase L): to have an array (bob, joe, fred) converted to:
      `"bob","joe","fred"`
      + `%T` to have a unix timestamp converted to MySQL Datetime format or `NULL`
      + `%t` to have a unix timestamp converted to MySQL Datetime format
  - `debug($sql[, args])`: same syntax as `run()`, but prints out both the SQL
    used and the query results.
  - `pretend($sql[, args])`: same syntax as `run()`, but it only prints out the
    final SQL and does not actually run the query.
  - `last_error()`: Get the last error on this connection
  - `get_enum_values($table, $column)`: for an `ENUM` type column, query the
    database for a list of the valid values.
  - `get_set_values($table, $column)`: Same, but for sets
  - `insert_or_update($table, $idcol, $idnum = NULL, [column data trios]`:
    Upsert helper method.
    For example, to `INSERT` or `UPDATE` a user (depending on whether or not
    `$user->id` is null:

      ```PHP
      insert_or_update('users', 'uid', $user->id,
                       'name', '%n', $user->name, // col name, format str, arg
                       'last_access', 'NOW()', NULL);// col name, format str, arg
      ```
  - `update($table, $idcol, $idnum = NULL, [column data trios]`: Same as above,
    but will only `UPDATE` the row.
  - `print_edit_form($table, $id = NULL, array $want_columns = null)`: Print
    an HTML table-based form that can be used to edit the row with primary key
    `$id` in the table `$table`. By default the column names/types are loaded 
    from the database. `$want_columns` can be used to only include a subset
    of columns.
* __BWMJournalledDatabase__: Matches the interface of `BWMDatabase`, but records
    all database changes in a second database. Can be used to synchronize a 
    database from a dev/staging server to the live site, with complete manual
    control over what rows/tables get synchronized.
    + `ignore_table($t, $ignore = true)`: Ignore (don't record) SQL commands
      that modify the table `$t`.
* __BWMDBObject__: abstract ORM base class that can be used to quickly build 
  database-backed classes (see `user.php` example)


Methods
-------
* `_post($v)`: clean Post - returns a useable `$_POST` variable or NULL if and 
  only if it is not set. This will `stripslashes()` automatically if needed.
* `_postn($v)`: clean Post - returns a useable `$_POST` variable or NULL if the
  var is either only whitespace ("", " ", etc.) or not set
* `_get($v)`: clean Get - returns a useable `$_GET` variable
* `_getn($v)`: clean Get - returns a useable `$_GET` variable or NULL if the var
  is either only whitespace ("", " ", etc.) or not set
* `_pog($v)`: clean Post Or Get - returns a useable request variable
* `etrim($str, $max_length = 35)`: Ensure `$str` is no longer than 
  `$max_length`, shortening and adding an ellipsis as needed
* `print_array($a)`: `print('<pre>'); print_r($a); print('</pre><br />');`
* `_eor(...)`: Either or - returns first non-empty argument
* `bwm_filesize_str($file_or_size, $nonexistent_return = 'error')`: Given a 
  file name or integer size in bytes, return a friendly file size string, e.g.
  `17.2 kB`
* `bwm_hmac($key, $data, $hash = 'md5', $blocksize = 64)`: HMAC
* `bwm_validate_email($email)`: Validate an email address, properly
  ([source](http://www.linuxjournal.com/article/9585))