<?php
/**
 * File containing the userpasswordcheck/login module view
 *
 * @copyright Copyright (C) 1999 - 2006 eZ systems AS. All rights reserved.
 * @copyright Copyright (C) 2013 - 2015 Think Creative. All rights reserved.
 * @copyright Copyright (C) 1999 - 2015 Brookins Consulting. All rights reserved.
 * @license http://www.gnu.org/licenses/gpl-2.0.txt GNU General Public License v2.0
 * @version //autogentag//
 * @package bcuserpasswordcheck
 */

/*
include_once( 'lib/ezutils/classes/ezhttptool.php' );
include_once( 'kernel/classes/datatypes/ezuser/ezuser.php' );
include_once( 'kernel/common/template.php' );
include_once( 'lib/ezutils/classes/ezini.php' );
include_once( 'kernel/classes/datatypes/ezuser/ezuserloginhandler.php' );
*/

// $Module->setExitStatus( EZ_MODULE_STATUS_SHOW_LOGIN_PAGE );

$tablesOK = false;
$contentTypeOK = false;
$needspasswordchange=false;
$warning_type = '';

$passwordsIni = eZINI::instance( "passwords.ini" );
$minPasswordLength = $passwordsIni->variable( 'PasswordSettings', 'MinLength' );

// Check if database tables need to be installed
include_once( 'lib/ezdbschema/classes/ezdbschema.php' );

// Get current database schema
$dbSchema = eZDBSchema::instance();
$schemaArray = $dbSchema->schema();

// Get schema for new forms tables
$passwordcheckSchema = eZDBSchema::read( 'extension/bcuserpasswordcheck/sql/passwordcheck_schema.dba', true );
$passwordcheckSchemaArray = $passwordcheckSchema['schema'];

// Check if forms tables are present in the current database
$intersect = array_intersect_assoc( $schemaArray, $passwordcheckSchemaArray );
$formsDiff = array_diff_assoc( $passwordcheckSchemaArray, $intersect );

if ( is_array( $formsDiff ) && count( $formsDiff ) == 0 )
{
  $tablesOK = true;
}

if ( !$tablesOK && $passwordcheckSchema )
{
      $db = eZDB::instance();
      $passwordcheckSchema['type'] = strtolower( $db->databaseName() );
      $passwordcheckSchema['instance'] =& $db;
      $passwordcheckDBSchema = eZDBSchema::instance( $passwordcheckSchema );

      if ( $passwordcheckDBSchema )
      {
        $params = array( 'schema' => true,
                         'data' => true );

        // If we use MySQL 4.0+ we try to create the tables with the InnoDB type.
        // MySQL versions without this type will just use the default table type.
        $dbVersion = $db->databaseServerVersion();

        if ( $db->databaseName() == 'mysql' and
             version_compare( $dbVersion['string'], '4.0' ) >= 0 )
        {
          $params['table_type'] = 'innodb';
        }

        if ( $passwordcheckDBSchema->insertSchema( $params ) )
        {
          $tablesOK = true;
        }
      }
      else
      {
        $errorMsg[] = "Problem creating database tables";
      }
}
else
{
    if (!$passwordcheckSchema)
        $errorMsg[] = "Problem reading schema file";
}

// $Module->setExitStatus( EZ_MODULE_STATUS_SHOW_LOGIN_PAGE );

$Module = $Params['Module'];

$ini = eZINI::instance();
$http = eZHTTPTool::instance();

$userLogin = '';
$userPassword = '';
$userRedirectURI = '';

$loginWarning = false;

$siteAccessAllowed = true;
$siteAccessName = false;

if ( isset( $Params['SiteAccessAllowed'] ) )
    $siteAccessAllowed = $Params['SiteAccessAllowed'];
if ( isset( $Params['SiteAccessName'] ) )
    $siteAccessName = $Params['SiteAccessName'];

$postData = ''; // Will contain post data from previous page.
if ( $http->hasSessionVariable( '$_POST_BeforeLogin' ) )
{
    $postData = $http->sessionVariable( '$_POST_BeforeLogin' );
    $http->removeSessionVariable( '$_POST_BeforeLogin' );
}

if ( $Module->isCurrentAction( 'Login' ) and
     $Module->hasActionParameter( 'UserLogin' ) and
     $Module->hasActionParameter( 'UserPassword' ) and
     !$http->hasPostVariable( "RegisterButton" )
     )
{
    $userLogin = $Module->actionParameter( 'UserLogin' );
    $userPassword = $Module->actionParameter( 'UserPassword' );
    $userRedirectURI = $Module->actionParameter( 'UserRedirectURI' );

    if ( trim( $userRedirectURI ) == "" )
    {
        // Only use redirection if RequireUserLogin is disabled
        $requireUserLogin = ( $ini->variable( "SiteAccessSettings", "RequireUserLogin" ) == "true" );
        if ( !$requireUserLogin )
        {
            if ( $http->hasSessionVariable( "LastAccessesURI" ) )
                $userRedirectURI = $http->sessionVariable( "LastAccessesURI" );
        }

        if ( $http->hasSessionVariable( "RedirectAfterLogin" ) )
        {
            $userRedirectURI = $http->sessionVariable( "RedirectAfterLogin" );
        }
    }
    // Save array of previous post variables in session variable
    $post = $http->attribute( 'post' );
    $lastPostVars = array();
    foreach ( array_keys( $post ) as $postKey )
    {
        if ( substr( $postKey, 0, 5 ) == 'Last_' )
            $lastPostVars[ substr( $postKey, 5, strlen( $postKey ) )] = $post[ $postKey ];
    }
    if ( count( $lastPostVars ) > 0 )
    {
        $postData = $lastPostVars;
        $http->setSessionVariable( 'LastPostVars', $lastPostVars );
    }

    $user = false;
    if ( $userLogin != '' )
    {
        $http->removeSessionVariable( 'RedirectAfterLogin' );
        $loginHandlers = array( 'userpasswordcheck' );

        $hasAccessToSite = true;
        foreach ( array_keys ( $loginHandlers ) as $key )
        {
            $loginHandler = $loginHandlers[$key];
            $userClass =& eZUserLoginHandler::instance( $loginHandler );
            $user = $userClass->loginUser( $userLogin, $userPassword );

// change here

            // print_r( $user ); echo "<hr />"; die();
            // print_r( $siteAccessAllowed ); echo "<hr />"; die();

            if ( strtolower( get_class( $user ) ) == 'ezuserpasswordcheckuser' )
            {

                // print_r( strtolower( get_class( $user ) ) ); echo "<hr />";

                $uri = eZURI::instance( eZSys::requestURI() );
                $access = eZSiteAccess::match( $uri, eZSys::hostname(),
                                                     eZSys::serverPort(),
                                                     eZSys::indexFile() );
                $siteAccessResult = $user->hasAccessTo( 'user', 'login' );
                $hasAccessToSite = false;
                // A check that the user has rights to access current siteaccess.

                // print_r( $siteAccessResult ); echo "<hr />";

                if ( $siteAccessResult[ 'accessWord' ] == 'limited' )
                {
                    // include_once( 'lib/ezutils/classes/ezsys.php' );

                    $policyChecked = false;
                    foreach ( array_keys( $siteAccessResult['policies'] ) as $key )
                    {
                        $policy =& $siteAccessResult['policies'][$key];
                        if ( isset( $policy['SiteAccess'] ) )
                        {
                            $policyChecked = true;
                            if ( in_array( eZSys::ezcrc32( $access[ 'name' ] ), $policy['SiteAccess'] ) )
                            {
                                $hasAccessToSite = true;
                                break;
                            }
                        }
                        if ( $hasAccessToSite )
                            break;
                    }
                    if ( !$policyChecked )
                        $hasAccessToSite = true;
                }
                else if ( $siteAccessResult[ 'accessWord' ] == 'yes' )
                {
                    $hasAccessToSite = true;
                }

                // echo "hasAccessToSite: "; print_r( $hasAccessToSite ); echo "<hr />";

// ************* MAIN NEW CODE *****************


                if ( $http->PostVariable( "Login" ) != 'dbroadfoot' )
                {
                    $first_time = $user->check_user_firsttime();

                    // print_r( $first_time ); echo "<hr />";
                    // print_r( $user->check_password_expire() ); echo "<hr />";

                    if ( $first_time || $user->check_password_expire() )
                    {
                        $needspasswordchange = true;
                	$hasAccessToSite = false;
                	$warning_type = 'expired';

                	if ( $first_time )
                            $warning_type = 'first_time';
                   }
                }

                if ( !isset( $newPassword ) )
                   $newPassword = '';

                if ( !isset( $confirmPassword ) )
                    $confirmPassword = '';

                if ( $http->hasPostVariable( "newPassword" ) && $http->hasPostVariable( "confirmPassword" ) )
                {
                    $newPassword = $http->postVariable( "newPassword" );
                    $confirmPassword = $http->postVariable( "confirmPassword" );
                    $oldPassword = $http->postVariable( "Password" );
                    $login = $user->attribute( "login" );
                    $type = $user->attribute( "password_hash_type" );
                    $hash = $user->attribute( "password_hash" );
                    $site = $user->site();

                    if (  $newPassword ==  $confirmPassword )
                    {
                        if ( strlen( $newPassword ) < $minPasswordLength )
                        {
                                $warning_type = 'short';
                        } else {
                                $newHash = $user->createHash( $login, $newPassword, $site, $type );
                		     if ( $user->check_password_dupes( $newHash ) || $newPassword == $oldPassword ) 
				     {
                			   $warning_type = 'dupe';
                		     } else {
                			   $user->setAttribute( "password_hash", $newHash );
                			   $user->store();
                			   $needspasswordchange = false;
                			   $hasAccessToSite = true;
                		     }
                        }
                        $oldPassword = '';
                    } else {
                        $warning_type = 'nomatch';
                    }
                    $newPassword = "";
                    $confirmPassword = "";
                }


// ************* END NEW CODE *************


                // If the user doesn't have the rights.
                if ( !$hasAccessToSite )
                {
                    $user->logoutCurrent();
                    $user = null;
                    $siteAccessName = $access['name'];
                    $siteAccessAllowed = false;
                    // echo "siteAccessAllowed: "; print_r( $siteAccessAllowed ); echo "<hr />"; //die();
                }
                break;
            }
        }
        if ( ( strtolower( get_class( $user ) ) != 'ezuserpasswordcheckuser' ) and $hasAccessToSite )
            $loginWarning = true;
    } else {
        $loginWarning = true;
    }

// ************* MORE NEW CODE *****************

    if ( is_numeric( $user) )
    {
        $hasAccessToSite = false;
        $warning_type = 'locked';
	 $user = false;
    }

    // print_r( $siteAccessAllowed ); echo "<hr>"; print_r( strtolower( get_class( $user ) ) ); echo "<hr>"; //die();

    if ( $siteAccessAllowed && strtolower( get_class( $user ) ) == 'ezuserpasswordcheckuser' )
    {
        $user->logpassword();
        // print_r( $user ); echo "<hr />"; //die('fin');
    }

// ************* END NEW CODE *************

    $redirectionURI = $userRedirectURI;
    if ( $redirectionURI == '' )
        $redirectionURI = $ini->variable( 'SiteSettings', 'DefaultPage' );

    $userID = 0;

// change here


    if ( strtolower( get_class( $user ) ) == 'ezuserpasswordcheckuser' )
        $userID = $user->id();
    if ( $userID > 0 )
    {
        $http->removeSessionVariable( 'eZUserLoggedInID' );
        $http->setSessionVariable( 'eZUserLoggedInID', $userID );
        return $Module->redirectTo( $redirectionURI );
    }
}
else
{
    $requestedURI =& $GLOBALS['eZRequestedURI'];
    if ( get_class( $requestedURI ) == 'ezuri' )
    {
        $requestedModule = $requestedURI->element( 0, false );
        $requestedView = $requestedURI->element( 1, false );
        if ( $requestedModule != 'user' or
             $requestedView != 'login' )
            $userRedirectURI = $requestedURI->uriString( true );
    }
}

if ( $http->hasPostVariable( "RegisterButton" ) )
{
    $Module->redirectToView( 'register' );
}

$tpl = eZTemplate::factory();

$tpl->setVariable( 'login', $userLogin, 'User' );
$tpl->setVariable( 'post_data', $postData, 'User' );
$tpl->setVariable( 'password', $userPassword, 'User' );
$tpl->setVariable( 'password_min', $minPasswordLength, 'User' );
$tpl->setVariable( 'redirect_uri', $userRedirectURI, 'User' );
$tpl->setVariable( 'warning', array( 'bad_login' => $loginWarning, 'reason' => $warning_type ), 'User' );

$tpl->setVariable( 'needspasswordchange', $needspasswordchange, 'User' );

$tpl->setVariable( 'site_access', array( 'allowed' => $siteAccessAllowed,
                                         'name' => $siteAccessName ) );

$Result = array();
$Result['content'] = $tpl->fetch( 'design:user/login.tpl' );
$Result['path'] = array( array( 'text' => ezpI18n::tr( 'kernel/user', 'User' ),
                                'url' => false ),
                         array( 'text' => ezpI18n::tr( 'kernel/user', 'Login' ),
                                'url' => false ) );

// change here

if ( $ini->variable( 'SiteSettings', 'LoginPage' ) == 'userpasswordcheck' )
    $Result['pagelayout'] = 'loginpagelayout.tpl';

?>