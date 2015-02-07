{* Warnings *}
{section show=$User:warning.bad_login}
<div class="message-warning">
<h2><span class="time">[{currentdate()|l10n( shortdatetime )}]</span> {'The system could not log you in.'|i18n( 'design/admin/user/login' )}</h2>
<ul>
    <li>{'Make sure that the username and password is correct.'|i18n( 'design/admin/user/login' )}</li>
    <li>{'All letters must be typed in using the correct case.'|i18n( 'design/admin/user/login' )}</li>
    <li>{'Please try again or contact the site administrator.'|i18n( 'design/admin/user/login' )}</li>
</ul>
</div>
{section-else}
{section show=$site_access.allowed|not}
<div class="message-warning">
<h2><span class="time">[{currentdate()|l10n( shortdatetime )}]</span> {'Access denied!'|i18n( 'design/admin/user/login' )}</h2>
<ul>
{if $User:needspasswordchange}
    <li>{'Your pasword has expired for <%siteaccess_name>.'|i18n( 'design/admin/user/login',, hash( '%siteaccess_name', $site_access.name ) )|wash}</li>
    <li>{'Please select a new password by completing the additional fields below.'|i18n( 'design/admin/user/login',, hash( '%siteaccess_name', $site_access.name ) )|wash}</li>
{else}
    <li>{'You do not have permissions to access <%siteaccess_name>.'|i18n( 'design/admin/user/login',, hash( '%siteaccess_name', $site_access.name ) )|wash}</li>
    <li>{'Please contact the site administrator.'|i18n( 'design/admin/user/login' )}</li>
{/if}
</ul>
</div>
{/section}
{/section}

{* Login window *}
<div class="context-block">

<form name="loginform" method="post" action={'/user/login/'|ezurl}>

{* DESIGN: Header START *}<div class="box-header"><div class="box-tc"><div class="box-ml"><div class="box-mr"><div class="box-tl"><div class="box-tr">

<h1 class="context-title">{'Log in to the administration interface of eZ publish'|i18n( 'design/admin/user/login' )}</h1>

{* DESIGN: Mainline *}<div class="header-mainline"></div>

{* DESIGN: Header END *}</div></div></div></div></div></div>

{* DESIGN: Content START *}<div class="box-ml"><div class="box-mr"><div class="box-content">

<div class="context-attributes">

<div class="block">
    <p>{'Please enter a valid username/password combination and click "Log in".'|i18n( 'design/admin/user/login' )}</p>
    <p>{'Use the "Register" button to create a new account.'|i18n( 'design/admin/user/login' )}</p>
</div>

<div class="block">
    <label for="id1">{'Username'|i18n( 'design/admin/user/login' )}:</label>
    <input class="halfbox" type="text" size="10" name="Login" id="id1" value="{$User:login|wash}" tabindex="1" title="{'Enter a valid username into this field.'|i18n( 'design/admin/user/login' )}" />
</div>

<div class="block">
    <label for="id2">{'Password'|i18n( 'design/admin/user/login' )}:</label>
    <input class="halfbox" type="password" size="10" name="Password" id="id2" value="" tabindex="1" title="{'Enter a valid password into this field.'|i18n( 'design/admin/user/login' )}" />
</div>

{if $User:needspasswordchange}

<div class="block">
    <label for="id3">{'New Password'|i18n( 'design/admin/user/login' )}:</label>
    <input class="halfbox" type="password" size="10" name="newPassword" id="id3" value="" tabindex="1" title="{'Enter a new valid password into this field.'|i18n( 'design/admin/user/login' )}" />
</div>

<div class="block">
    <label for="id4">{'Confirm New Password'|i18n( 'design/admin/user/login' )}:</label>
    <input class="halfbox" type="password" size="10" name="confirmPassword" id="id4" value="" tabindex="1" title="{'Confirm the new valid password into this field.'|i18n( 'design/admin/user/login' )}" />
</div>

{/if}

</div>

{* DESIGN: Content END *}</div></div></div>

<div class="controlbar">
{* DESIGN: Control bar START *}<div class="box-bc"><div class="box-ml"><div class="box-mr"><div class="box-tc"><div class="box-bl"><div class="box-br">
<div class="block">
    <input class="button" type="submit" name="LoginButton" value="{'Log in'|i18n( 'design/admin/user/login', 'Login button' )}" tabindex="1" title="{'Click here to log in using the username/password combination entered in the fields above.'|i18n( 'design/admin/user/login' )}" />
    <input class="button" type="submit" name="RegisterButton" value="{'Register'|i18n( 'design/admin/user/login', 'Register button' )}" tabindex="1" title="{'Click here to create a new account.'|i18n( 'design/admin/user/login' )}" />
</div>
{* DESIGN: Control bar END *}</div></div></div></div></div></div>
</div>

<input type="hidden" name="RedirectURI" value="{$User:redirect_uri|wash}" />

</form>

</div>

<p><a href="/user/forgotpassword">Forgot password?</a>


{literal}
<script language="JavaScript" type="text/javascript">
<!--
    window.onload=function()
    {
        document.getElementById('id1').focus();
    }
-->
</script>
{/literal}
