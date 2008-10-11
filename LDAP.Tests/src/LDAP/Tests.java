/**
 * 
 */
package LDAP;

import java.io.IOException;
import java.util.Hashtable;
import java.util.regex.*;
import javax.naming.*;
import javax.naming.directory.*;

/**
 * @author Justin Dearing
 *
 */
public class Tests {

	/**
	 * Prints out info needed to automatically detect the settings for
	 * connecting to the domain controller your user authenticated against.
	 * If you are logged into an AD domain on Microsoft Windows,
	 * this should be able to tell you the ldap url and user name. 
	 * All you should need to provide is a password. 
	 * @param args
	 */
	public static void main(String[] args) throws IOException 
	{
		String osName = System.getProperty("os.name");
		String osArch = System.getProperty("os.arch");

		System.out.println("OS Name: " + osName);
		System.out.println("OS Architecture: " + osArch);
		
		// This is a more accurate OS check for our purposes. We don't care about 95/98/ME
		// I need to find a way to eliminate Pre Win2K versions of NT
		String osEnv = System.getenv("OS");
		if (!osEnv.equalsIgnoreCase("Windows_NT"))
		{
			return;
		} 
		
		System.out.println("This machine appears to be running Windows. Detecting AD info");
		
		String domainController = System.getenv("LOGONSERVER");
		// Thats a regex for '\\' You need to escape out the slashes for the string
		// and then you need to escape it out for the regex parser. 
		if(domainController != null)
		{
			// It seems that if we login via the RUNAS command the envirormental
			// variable LOGONSERVER does not get set.
			domainController = domainController.replaceFirst("\\\\\\\\", "");
			System.out.println("Domain controller: " + domainController);
		}		
		
		String systemUserName = System.getenv("USERNAME");
		String domain = System.getenv("USERDNSDOMAIN");
		
		if (domain == null)
		{
			System.out.println("You do not appear to be logged as an AD domain user.");
			return;
		}
		
		String ldapUrl = String.format("ldap://%s:389", domainController);
		String ldapBaseDN = "dc=" + domain.replaceAll("\\.", ",dc=");
		String ldapUserName = String.format("%s@%s", systemUserName, domain);
		String ldapPassword = "";
		
		System.out.println("Ldap server URL: " + ldapUrl);
		System.out.println("Ldap base dn: " + ldapBaseDN);
		System.out.println("Ldap login name: " + ldapUserName);
		System.out.println("Enter your AD password: ");
		
		{
			char l = '\0';
			while (l != '\n' && l != '\r')
			{
				l = (char)System.in.read();
				ldapPassword += l;
			}
			ldapPassword = ldapPassword.replaceAll("[\\r\\n]", "");
		}
		//System.out.println("Ldap password: " + ldapPassword);
		
		//*		
		try {
			activeDirectoryTest(ldapUrl, ldapBaseDN, ldapUserName, ldapPassword);
		}
		catch (Exception ex){
			System.err.println("Error occured: " + ex.getMessage());
		}
		//*/
	}
	
	
	/**
	 * Logs into Active Directory and gets the authenticated user's group membership info.
	 * @param ldapUrl The ldap url of the Active Directory Domain controller.
	 * @param baseDN The root dn of the AD domain you authenticate against.
	 * @param userName The user name to authenticate to the active directory server as.
	 * @param password The password to login to Active Directory with.
	 * @throws NamingException 
	 */
	private static void activeDirectoryTest(String ldapUrl, String baseDN, String userName, String password) throws NamingException
	{
		Hashtable<String, String> env = new Hashtable<String, String>();
		env.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, ldapUrl + '/' + baseDN);
		env.put(Context.SECURITY_AUTHENTICATION, "simple");		// 'simple' = username + password
		env.put(Context.SECURITY_PRINCIPAL, userName);			// add the full user DN in active directories case the user@domain form is acceptable. 
		env.put(Context.SECURITY_CREDENTIALS, password);
		DirContext ctx = new InitialDirContext(env);
		
		//StringBuilder sb = new StringBuilder();
		//sb.append("(&(userPrincipalName=");
		//sb.append(userName);
		//sb.Append(")(objectClass=user))");
		//ctx.search(name, filter, cons)  //("distinguishedName", "(&(member=CN=Lance Robinson,CN=Users,DC=JUNGLE)(objectcategory=group))", cons)
		// (&(member=CN=Lance Robinson,CN=Users,DC=JUNGLE)(objectcategory=group))
	}
	

}
