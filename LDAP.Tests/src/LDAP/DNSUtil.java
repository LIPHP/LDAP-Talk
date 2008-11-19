package LDAP;

import java.util.Hashtable;

import javax.naming.NamingException;
import javax.naming.directory.*;



/**
 * Utility class to perform DNS lookups. Taken from a class written by Matt Tucker.
 * LDAP lookup function written by Justin Dearing.
 * @see http://mail.jabber.org/pipermail/jdev/2005-February/021039.html
 * @author Matt Tucker
 * @author Justin Dearing
 */
public class DNSUtil {

    private static DirContext context; 
    static {
        try {
            Hashtable env = new Hashtable();
            env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
            context = new InitialDirContext(env);
        }
        catch (Exception e) {
        	System.out.println(e.toString());
            //Log.error(e);
        }
    }
    
    /**
     * Returns the host name and port that the specified domains ldap server can be
     * reached at for. A DNS lookup for a SRV record in the form "_ldap._tcp.example.com"
     * is attempted, according to section 14.4 of RFC 3920. If that
     * lookup fails as well, it's assumed that the LDAP server lives at the
     * host resolved by a DNS lookup at the specified domain on the default port
     * of 389.<p>
     *
     * As an example, a lookup for "example.com" may return "sbs.example.com:389".
     *
     * @param domain the domain.
     * @return a HostAddress, which encompasses the hostname and port that the XMPP
     *      server can be reached at for the specified domain.
     * @author Justin Dearing
     * @throws NamingException 
     * @todo return an array of all ldap servers for the domain.
     */
    public static HostAddress resolveLdapServers(String domain) throws NamingException 
    {
        if (context == null) {
            return new HostAddress(domain, 389);
        }
        String host = domain;
        int port = 389;
        
        Attributes dnsLookup = context.getAttributes("_ldap._tcp." + domain);
        String srvRecord = (String)dnsLookup.get("SRV").get();
        String [] srvRecordEntries = srvRecord.split(" ");
        port = Integer.parseInt(srvRecordEntries[srvRecordEntries.length-2]);
        host = srvRecordEntries[srvRecordEntries.length-1];

        // Host entries in DNS should end with a ".".
        if (host.endsWith(".")) {
            host = host.substring(0, host.length()-1);
        }
        return new HostAddress(host, port);
    } 
    
    /**
     * Returns the host name and port that the specified XMPP server can be
     * reached at for server-to-server communication. A DNS lookup for a SRV
     * record in the form "_xmpp-server._tcp.example.com" is attempted, according
     * to section 14.4 of RFC 3920. If that lookup fails, a lookup in the older form
     * of "_jabber._tcp.example.com" is attempted since servers that implement an
     * older version of the protocol may be listed using that notation. If that
     * lookup fails as well, it's assumed that the XMPP server lives at the
     * host resolved by a DNS lookup at the specified domain on the default port
     * of 5269.<p>
     *
     * As an example, a lookup for "example.com" may return "im.example.com:5269".
     *
     * @param domain the domain.
     * @return a HostAddress, which encompasses the hostname and port that the XMPP
     *      server can be reached at for the specified domain.
     * @throws NamingException 
     */
    public static HostAddress resolveXMPPDomain(String domain) throws NamingException {
        if (context == null) {
            return new HostAddress(domain, 5269);
        }
        String host = domain;
        int port = 5269;
        try {
            Attributes dnsLookup = context.getAttributes("_xmpp-server._tcp." + domain);
            String srvRecord = (String)dnsLookup.get("SRV").get();
            String [] srvRecordEntries = srvRecord.split(" ");
            port = Integer.parseInt(srvRecordEntries[srvRecordEntries.length-2]);
            host = srvRecordEntries[srvRecordEntries.length-1];
        }
        catch (Exception e) {
        	// Attempt lookup with older "jabber" name.
        	Attributes dnsLookup = context.getAttributes("_jabber._tcp." + domain);
        	String srvRecord = (String)dnsLookup.get("SRV").get();
        	String [] srvRecordEntries = srvRecord.split(" ");
        	port = Integer.parseInt(srvRecordEntries[srvRecordEntries.length-2]);
        	host = srvRecordEntries[srvRecordEntries.length-1];
            
        }
        // Host entries in DNS should end with a ".".
        if (host.endsWith(".")) {
            host = host.substring(0, host.length()-1);
        }
        return new HostAddress(domain, port);
    } 
    /**
     * Encapsulates a hostname and port.
     */
    public static class HostAddress { 
        private String host;
        private int port; 
        private HostAddress(String host, int port) {
            this.host = host;
            this.port = port;
        } 
        /**
         * Returns the hostname.
         *
         * @return the hostname.
         */
        public String getHost() {
            return host;
        } 
        /**
         * Returns the port.
         *
         * @return the port.
         */
        public int getPort() {
            return port;
        } 
        public String toString() {
            return host + ":" + port;
        }
    }
}  