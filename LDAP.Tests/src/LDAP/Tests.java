/**
 * 
 */
package LDAP;

import java.io.IOException;

/**
 * @author justin.dearing
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
		String ldapUserName = String.format("%s@%s", systemUserName, domain);
		String ldapPassword = "";
		
		System.out.println("Ldap server URL: " + ldapUrl);
		System.out.println("Ldap login name: " + ldapUserName);
		System.out.println("Enter your AD password: ");
		
		{
			char l = '\0';
			while (l != '\n')
			{
				l = (char)System.in.read();
				ldapPassword += l;		
			}
		}
		System.out.println("Ldap password: " + ldapPassword);
		
	}
	
	
	/**
	 * Logs into Active Directory and gets the logded in users group info.
	 * @param ldapUrl The ldap url of the Active Directory Domain controller.
	 * @param userName The user name to authenticate to the active directory server as.
	 * @param password The password to login to Active Directory with.
	 */
	private static void activeDirectoryTest(String ldapUrl, String userName, String password) throws NoSuchMethodException
	{
		throw new NoSuchMethodException("LDAP.Tests.activeDirectoryTest() has yet to be written.");
	}
	

}
