/**
 * 
 */
package LDAP;

import java.io.IOException;
import java.net.*;
import java.util.*;
import javax.naming.*;
import javax.naming.directory.*;

import LDAP.DNSUtil.HostAddress;

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
	 * @throws NamingException 
	 */
	public static void main(String[] args) throws IOException, NamingException 
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
		
		String systemUserName = System.getenv("USERNAME");
		String domain = System.getenv("USERDNSDOMAIN");
		
		if (domain == null)
		{
			System.out.println("You do not appear to be logged as an AD domain user.");
			return;
		}
		
		String ldapBaseDN = "dc=" + domain.replaceAll("\\.", ",dc=");
		String ldapUserName = String.format("%s@%s", systemUserName, domain);
		String ldapPassword = "";
		
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
		
		HostAddress ldapServer = DNSUtil.resolveLdapServers(domain);
		
		//*		
		try {
			//String [] ldapHosts = new String[] {domain, domainController};
			String [] ldapHosts = new String[] {ldapServer.getHost()};
			activeDirectoryTest(ldapHosts, ldapBaseDN, ldapUserName, ldapPassword);
		}
		catch (Exception ex){
			System.err.println("Error occured: " + ex.getMessage());
		}
		//*/
	}
	
	
	/**
	 * Logs into Active Directory and gets the authenticated user's group membership info.
	 * Found some of this code in the sun forums.
	 * @see http://forums.sun.com/thread.jspa?messageID=3012764
	 * @param ldapServers A lost of potential LDAP servers for the active directory.
	 * @param baseDN The root dn of the AD domain you authenticate against.
	 * @param userName The user name to authenticate to the active directory server as.
	 * @param password The password to login to Active Directory with.
	 * @throws NamingException 
	 */
	private static void activeDirectoryTest(String[] ldapServers, String baseDN, String userName, String password) throws NamingException
	{
		// HashTable mapping group DNs to groupNames
		Hashtable<String, String> groups = new Hashtable<String, String>();
		
		try {
			//Create the initial directory context
			DirContext ctx = getLdapConnection(ldapServers, userName, password);
			
			//Create the search controls 		
			SearchControls searchCtls = new SearchControls();
		
			//Specify the search scope
			searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
 
			//specify the LDAP search filter			
			String searchFilter;
			{
				// There is no particular reason go out of our way to limit the scope of this StringBuilder
				StringBuilder sb = new StringBuilder();
				sb.append("(&(objectClass=user)(userPrincipalName=");
				sb.append(userName);
				sb.append("))");
				searchFilter = sb.toString();
			}
			
			//initialize counter to total the group members
			int totalResults = 0;
 
			//Specify the attributes to return
			String returnedAtts[]={"memberOf"};
			searchCtls.setReturningAttributes(returnedAtts);
		
			//Search for objects using the filter
			NamingEnumeration answer = ctx.search(baseDN, searchFilter, searchCtls);
			
			//Loop through the search results
			while (answer.hasMoreElements()) {
				SearchResult sr = (SearchResult)answer.next();
 
				System.out.println(">>>" + sr.getName());
 
				//Print out the groups
 
				Attributes attrs = sr.getAttributes();
				if (attrs != null) {
 
					try
					{
						for (NamingEnumeration ae = attrs.getAll();ae.hasMore();) {
							Attribute attr = (Attribute)ae.next();
							for (NamingEnumeration e = attr.getAll();e.hasMore();totalResults++)
							{
								String dn = e.next().toString();
								String cn = groupDN2CN(ctx, dn);
								if (cn == null) { cn = "unknown"; }
								groups.put(dn, cn);
							}
						}
					}	 
					catch (NamingException e)
					{
						System.err.println("Problem listing membership: " + e);
					}
				
				}
			}
 
			System.out.println("Total groups: " + totalResults);
			ctx.close();
		}
		catch (NamingException ex)	{
			Throwable innerEx = ex.getRootCause();
			if (innerEx instanceof UnknownHostException)
			{
				System.err.println("Host not found " + innerEx.getMessage() + '.');
			}
			else if(innerEx instanceof ConnectException)
			{
				System.err.println("Error connecting to " + innerEx.getMessage());
			}
			else if(innerEx instanceof AuthenticationException)
			{
				System.err.println("Authen " + innerEx.getMessage());
			}
			else
			{
				System.err.println("NamingException occured: " + ex);
			}
		}
		
		for(Enumeration<String> DNs = groups.keys(); DNs.hasMoreElements(); )
		{
			String dn = DNs.nextElement();
			String cn = groups.get(dn);
			System.out.println("[" + cn + "] " + dn);
		}
	}
	
	
	/**
	 * 
	 * @param ldapServers an array of hostnames to attempt to connect to via ldap. 
	 * The first server that is successfully authenticated against is used.
	 * @param userName The username to authenticate to the ldap server as.
	 * @param password The password to use in authenticating to the ldap server.
	 * @return
	 * @throws NamingException 
	 */
	private static DirContext getLdapConnection(String[] ldapServers, String userName, String password) throws NamingException 
	{
		DirContext ctx;
		Hashtable<String, String> env = new Hashtable<String, String>();
		
		env.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.SECURITY_AUTHENTICATION, "simple");		// 'simple' = username + password
		env.put(Context.SECURITY_PRINCIPAL, userName);			// add the full user DN in active directories case the user@domain form is acceptable. 
		env.put(Context.SECURITY_CREDENTIALS, password);
		
		for(String ldapServer:ldapServers)
		{
			String ldapUrl = String.format("ldap://%s:389", ldapServer);
			env.put(Context.PROVIDER_URL, ldapUrl);
			
			try {
				ctx = new InitialDirContext(env);
				if (ctx != null) { return ctx; }
			}
			catch (NamingException ex)
			{
				System.err.printf(Locale.getDefault(), "Cannot connect to %s. Error: %s", ldapServer, ex.getMessage());
			}
		}
		// If we made it hear die
		throw new NamingException("Could not connect to any LDAP servers.");
	}

	
	
	/**
	 * Queries the binded DirContext for the Cannonical Name of the distinguishedName.
	 * Basically, this is meant to transform the "LDAP name" of a group to its "Windows Name"
	 * @param ctx A Dircontext that is properly binded to an ldap server.
	 * @param distinguishedName The Fully qualified name of a group.
	 */
	private static String groupDN2CN (DirContext ctx, String distinguishedName)
	{
		// We only want the cn attribute
		SearchControls searchCtls = new SearchControls();
		searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		String returnedAtts[]={"cn"};
		searchCtls.setReturningAttributes(returnedAtts);
		
		String searchFilter;
		{
			// There is no particular reason go out of our way to limit the scope of this StringBuilder
			StringBuilder sb = new StringBuilder();
			sb.append("(&(objectClass=group)(distinguishedname=");
			sb.append(distinguishedName);
			sb.append("))");
			searchFilter = sb.toString();
		}
		try {
			NamingEnumeration answer = ctx.search(distinguishedName, searchFilter, searchCtls);
			String ret = null;
			
			//We should only get one result
			if (answer.hasMoreElements()) {
				SearchResult sr = (SearchResult)answer.next();
 
				 
				Attributes attrs = sr.getAttributes();
				if (attrs != null) {
 
					// We only need the first part of each for loop. Hence the break statements.
					for (NamingEnumeration ae = attrs.getAll();ae.hasMore();) {
						Attribute attr = (Attribute)ae.next();
						for (NamingEnumeration e = attr.getAll();e.hasMore();)
						{
							ret = e.next().toString();
							break;
						}
						break;
					}
				}
			}
			return ret;
		}
		catch (NamingException ex)	{
			System.err.println("NamingException occured: " + ex);
			return null;
		}
	}

}
