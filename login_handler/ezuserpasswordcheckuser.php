<?php
/**
 * File containing the eZUserPasswordCheckUser class.
 *
 * @copyright Copyright (C) 1999 - 2006 eZ systems AS. All rights reserved.
 * @copyright Copyright (C) 2013 - 2015 Think Creative. All rights reserved.
 * @copyright Copyright (C) 1999 - 2015 Brookins Consulting. All rights reserved.
 * @license http://www.gnu.org/licenses/gpl-2.0.txt GNU General Public License v2.0
 * @version //autogentag//
 * @package bcuserpasswordcheck
 */

class eZUserPasswordCheckUser extends eZUser
{
    function eZUserPasswordCheckUser( $row = array() )
    {
        $this->eZPersistentObject( $row );
        $this->OriginalPassword = false;
        $this->OriginalPasswordConfirm = false;
    }

    function preCollectUserInfo()
    {
        return array( 'module' => 'userpasswordcheck', 'function' => 'login' );
    }

    function postCollectUserInfo()
    {
        return true;
    }

    function add_password_fail()
    {
           $user_id = $this->attribute( 'contentobject_id' );
	    $db = eZDB::instance();
	    $query="UPDATE ezpassword_history set password_fails = password_fails + 1 where user_id= '$user_id'";
	    if ( $db->arrayQuery( $query ) )
            {
		    return true;
	    } else {
		    return false;
	    }
    }

    function get_password_fails()
    {
           $user_id = $this->attribute( 'contentobject_id' );
	    $db = eZDB::instance();
	    $query="select password_fails from ezpassword_history WHERE user_id= '$user_id'";
	    $fails =  $db->arrayQuery( $query );
	    return $fails[0]['password_fails'];
    }

    function clear_password_fails()
    {
           $user_id = $this->attribute( 'contentobject_id' );
	    $db = eZDB::instance();
	    $query="UPDATE ezpassword_history set password_fails = 0 where user_id= '$user_id'";
	    if ( $db->arrayQuery( $query ) )
            {
		    return true;
	    } else {
		    return false;
	    }
    }

    function check_user_firsttime()
    {

           $user_id = $this->attribute( 'contentobject_id' );
	    $db = eZDB::instance();
	    $query="select user_id from ezpassword_history where user_id= '$user_id'";
	    $user_ids =  $db->arrayQuery( $query );
	    if ( count( $user_ids ) == 0 )
            {
		    return true;
	    } else {
		    return false;
	    }
    }

    function check_password_expire()
    {
        $passwordsini = eZINI::instance( "passwords.ini" );
        $daysUntilExpire = $passwordsini->variable( 'PasswordSettings', 'DaysUntilExpire' );

        $password_hash = $this->attribute( 'password_hash' );
        $password_hash_type = $this->attribute( 'password_hash_type' );
        $timestamp = time();
	$comparetime = time() - ( 60*60*24*$daysUntilExpire );
        $user_id = $this->attribute( 'contentobject_id' );

        $db = eZDB::instance();
        $query="select timestamp from ezpassword_history where password_hash='$password_hash' and password_hash_type = '$password_hash_type' and user_id= '$user_id' and timestamp > $comparetime";
        $timestamps =  $db->arrayQuery( $query );

        if ( count( $timestamps ) == 0 )
        {
	    return true;
	}
        else
        {
	    return false;
        }
    }

    function check_password_dupes( $new_hash )
    {
          $password_hash_type = $this->attribute( 'password_hash_type' );
          $user_id = $this->attribute( 'contentobject_id' );
	   $db = eZDB::instance();
	   $query="select password_hash from ezpassword_history where password_hash='$new_hash' and password_hash_type = '$password_hash_type' and user_id= '$user_id'";
	   $password_hashes =  $db->arrayQuery( $query );
	   if ( count( $password_hashes ) == 0 )
           {
		return false;
	   } else {
		return true;
	   }
    }

    function logpassword()
    {
        $passwordsini = eZINI::instance( "passwords.ini" );
        $daysUntilExpire = $passwordsini->variable( 'PasswordSettings', 'DaysUntilExpire' );

        $password_hash = $this->attribute( 'password_hash' );
        $password_hash_type = $this->attribute( 'password_hash_type' );

        $timestamp = time();
        $comparetime = time() - ( 60*60*24*$daysUntilExpire );

        $user_id = $this->attribute( 'contentobject_id' );

        $db = eZDB::instance();
	$query="select timestamp from ezpassword_history where password_hash='$password_hash' and password_hash_type = '$password_hash_type' and user_id= '$user_id' and timestamp > $comparetime";
	$timestamps =  $db->arrayQuery( $query );

	if ( count( $timestamps ) == 0 )
        {
	    $db = eZDB::instance();
            $db->query( "INSERT INTO ezpassword_history ( password_hash, password_hash_type, timestamp, user_id ) VALUES ( '$password_hash', '$password_hash_type', '$timestamp', '$user_id')" );
        }
    }

    /*!
    \static
     Logs in the user if applied username and password is valid.
     \return The user object (eZContentObject) of the logged in user or \c false if it failed.
    */
    static function loginUser( $login, $password, $authenticationMatch = false )
    {
        $http = eZHTTPTool::instance();
        $db = eZDB::instance();

        $passwordsini = eZINI::instance( "passwords.ini" );
        $MaxRetries = $passwordsini->variable( 'PasswordSettings', 'MaxRetries' );

        if ( $authenticationMatch === false )
            $authenticationMatch = eZUser::authenticationMatch();

        $loginEscaped = $db->escapeString( $login );
        $passwordEscaped = $db->escapeString( $password );

        $loginArray = array();
        if ( $authenticationMatch & eZUser::AUTHENTICATE_LOGIN )
            $loginArray[] = "login='$loginEscaped'";
        if ( $authenticationMatch & eZUser::AUTHENTICATE_LOGIN )
        {
            if ( eZMail::validate( $login ) )
            {
                $loginArray[] = "email='$loginEscaped'";
            }
        }
        if ( count( $loginArray ) == 0 )
            $loginArray[] = "login='$loginEscaped'";
        $loginText = implode( ' OR ', $loginArray );

        $contentObjectStatus = eZContentObject::STATUS_PUBLISHED; // EZ_CONTENT_OBJECT_STATUS_PUBLISHED;

        $ini = eZINI::instance();
        $databaseImplementation = $ini->variable( 'DatabaseSettings', 'DatabaseImplementation' );
        // if mysql
        if ( $databaseImplementation == "ezmysql" )
        {
            $query = "SELECT contentobject_id, password_hash, password_hash_type, email, login
                      FROM ezuser, ezcontentobject
                      WHERE ( $loginText ) AND
                        ezcontentobject.status='$contentObjectStatus' AND
                        ezcontentobject.id=contentobject_id AND
                        ( ( password_hash_type!=4 ) OR
                          ( password_hash_type=4 AND ( $loginText ) AND password_hash=PASSWORD('$passwordEscaped') ) )";
        }
        else
        {
            $query = "SELECT contentobject_id, password_hash, password_hash_type, email, login
                      FROM ezuser, ezcontentobject
                      WHERE ( $loginText ) AND
                            ezcontentobject.status='$contentObjectStatus' AND
                            ezcontentobject.id=contentobject_id";
        }


        $users = $db->arrayQuery( $query );

        $exists = false;

        if ( $users !== false and count( $users ) >= 1 )
        {
            $ini = eZINI::instance();

            foreach ( array_keys( $users ) as $key )
            {
                $userRow =& $users[$key];
                $userID = $userRow['contentobject_id'];
                $hashType = $userRow['password_hash_type'];
                $hash = $userRow['password_hash'];
                $exists = eZUser::authenticateHash( $userRow['login'], $password, eZUser::site(),
                                                    $hashType,
                                                    $hash );

                // If hash type is MySQL
                if ( $hashType == eZUser::PASSWORD_HASH_MYSQL and $databaseImplementation == "ezmysql" )
                {
                    $queryMysqlUser = "SELECT contentobject_id, password_hash, password_hash_type, email, login
                              FROM ezuser, ezcontentobject
                              WHERE ezcontentobject.status='$contentObjectStatus' AND
                                    password_hash_type=4 AND ( $loginText ) AND password_hash=PASSWORD('$passwordEscaped') ";

                    $mysqlUsers = $db->arrayQuery( $queryMysqlUser );

                    if ( count( $mysqlUsers ) >= 1 )
                        $exists = true;
                }

                eZDebugSetting::writeDebug( 'kernel-user', eZUser::createHash( $userRow['login'], $password, eZUser::site(),
                                                                               $hashType ), "check hash" );
                eZDebugSetting::writeDebug( 'kernel-user', $hash, "stored hash" );

                if ( $exists )
                {
                    $userSetting = eZUserSetting::fetch( $userID );
                    $isEnabled = $userSetting->attribute( "is_enabled" );

                    if ( $hashType != eZUser::hashType() and
                         strtolower( $ini->variable( 'UserSettings', 'UpdateHash' ) ) == 'true' )
                    {
                        $hashType = eZUser::hashType();
                        $hash = eZUser::createHash( $login, $password, eZUser::site(),
                                                    $hashType );

                        $db->query( "UPDATE ezuser SET password_hash='$hash', password_hash_type='$hashType' WHERE contentobject_id='$userID'" );
                    }
                    break;
                }
            }
        }

        if ( $exists and $isEnabled )
        {
	    $user = new eZUserPasswordCheckUser( $userRow );
            $userID = $user->attribute( 'contentobject_id' );
	    $my_fails = $user->get_password_fails();

	    if ( $my_fails <= $MaxRetries )
            {
                $user->clear_password_fails();
                $oldUserID = $contentObjectID = $http->sessionVariable( "eZUserLoggedInID" );

                eZDebugSetting::writeDebug( 'kernel-user', $userRow, 'user row' );
                eZDebugSetting::writeDebug( 'kernel-user', $user, 'user' );

                eZUser::updateLastVisit( $userID );
                eZUser::setCurrentlyLoggedInUser( $user, $userID );
	    }
            else
            {
                $user = $my_fails;
	    }

            return $user;
        }
        else
        {
            $user = false;
            $query = "SELECT contentobject_id, password_hash, password_hash_type, email, login
                      FROM ezuser, ezcontentobject
                      WHERE ( $loginText ) AND
                            ezcontentobject.status='$contentObjectStatus' AND
                            ezcontentobject.id=contentobject_id";
	    $temp_mysqlUsers = $db->arrayQuery( $query );

            foreach ( array_keys( $temp_mysqlUsers ) as $key )
            {
                $temp_userRow =& $temp_mysqlUsers[$key];
		$temp_user = new eZUserPasswordCheckUser( $temp_userRow );

                //print_r( $temp_user ); echo "<hr />";

		$temp_user->add_password_fail();
		$my_fails = $temp_user->get_password_fails();

                // print_r( $my_fails ); echo "<hr />";

		if ( $my_fails > $MaxRetries ) $user = $my_fails;
	     }
             // die();

            return $user;
        }
    }
}

?>