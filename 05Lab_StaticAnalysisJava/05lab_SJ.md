# Static Analysis of Java Source Code

### Laboratory for the class “Security Verification and Testing” (01TYASM/01TYAOV)

### Politecnico di Torino – AY 2021/

### Prof. Riccardo Sisto

### prepared by:

### Riccardo Sisto (riccardo.sisto@polito.it)

### v. 1.0 (01/12/2021)

## Contents

1 Static Analysis of Java code with Spotbugs and FindSecBugs 2

```
1.1 Running SpotBugs on the OWASP Benchmark......................... 2
1.2 Analysis and Fix of the JettyEmbedded project (https://github.com/oktadeveloper/okta-spring-
boot-jetty-example)........................................ 2
1.3 Analysis and Fix of vulnerability CVE-2021-37573....................... 3
1.4 (Optional) Analysis of a Java project of your choice....................... 3
```
## Purpose of this laboratory

The purpose of this lab is to make experience with static source code analysis tools for the Java language.
More specifically, the lab focuses on the SpotBugs tool, which is integrated in the Eclipse IDE as a plugin,
extended with another plugin, called FindSecBugs, which is specific for finding security vulnerabilities. For
the installation of the tools, please refer to the gettingStartedv2.1.2.pdf guide.

All the material necessary for this lab can be found in the course web pages on didattica.polito.it, Materiale
Didattico 2021/22 section, 05LabStaticAnalysisJava folder, and the Dropbox folder.

## Getting started with Spotbugs and FindSecBugs

First of all, let us configure SpotBugs to find only security-related vulnerabilities. In Eclipse, open the Prefer-
ences item from the Window menu, and select Java - SpotBugs. Here, configure the plugin by checking only
the security box. Then, make sure FindSecBugs is correctly set in the plugins tab. Then, as a first test of the
tool, import the eclipse project available in the lab material, in the examples folder. Once the project has been
created, the maven utility inside Eclipse should download the project dependencies and compile the project
automatically. When the project setup and compilation are finished, run SpotBugs on the project (right click
on the project name and select SpotBugs - Find Bugs) and check that SpotBugs reports, as expected, some
vulnerabilities.

# Spotbugs vulnerability examples

1. 
```
	/**
	 * Returns all instances of the type.
	 *
	 * @return all entities
	 */
	Iterable<T> findAll();

  // Aggregate root
  // tag::get-aggregate-root[]
  @GetMapping("/employees")
  List<Employee> all() {
    return repository.findAll();
  }
```
warning saying that it could be dangerous to return the internal representation of objects to the outside

2. 
 ```  public String doSomething(HttpServletRequest request, String param) throws ServletException, IOException {

		String bar = "safe!"; // overwritten later, not safe!!
		java.util.HashMap<String,Object> map12212 = new java.util.HashMap<String,Object>();
		map12212.put("keyA-12212", "a-Value"); // put some stuff in the collection
		map12212.put("keyB-12212", param); // put it in a collection
		map12212.put("keyC", "another-Value"); // put some stuff in the collection
		bar = (String)map12212.get("keyB-12212"); // get it back out
        // if I don't overwrite bar, or we change bar=(String)map12212.get("keyC"); it would not be a vulnerability, but the program signals it anyway: false positive. 

            return bar; // (=param, which comes directly from the request!)
        }

		String param = "";
		if (request.getHeader("BenchmarkTest01090") != null) {
			param = request.getHeader("BenchmarkTest01090");
		}
		
		// URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
		param = java.net.URLDecoder.decode(param, "UTF-8");

 		String bar = new Test().doSomething(request, param);
		String sql = "SELECT * from USERS where USERNAME='foo' and PASSWORD='"+ bar +"'";
		// If I use a fixed string, tools does not report the warning
        
		try {
			java.sql.Statement statement = org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement();
			statement.addBatch( sql );
 ```
 ```
 Bug: org.owasp.benchmark.testcode.BenchmarkTest01090.doPost(HttpServletRequest, HttpServletResponse) passes a nonconstant String to an execute or addBatch method on an SQL statement
 The method invokes the execute or addBatch method on an SQL statement with a String     that seems to be dynamically generated. Consider using a prepared statement instead.    It is more efficient and less vulnerable to SQL injection attacks.
 ```
```
Is this a real vulnerability? Does bar come from an untrusted source? Yes! real vulnerability!
```
```
To fix we could filter bar so that it only contains alphanumeric characters, but better to use PreparedStatement!
```

## 1 Static Analysis of Java code with Spotbugs and FindSecBugs

### 1.1 Running SpotBugs on the OWASP Benchmark

Now, let us run the tool on the OWASP Benchmark. First of all, download the zip archive of the benchmark
project and extract it to a folder which is under your home. The zip archive (Benchmark-master.zip) is available
in the course Dropbox folder. In Eclipse, select the ’Open projects from File System’ item from the File menu
and select the folder where the Benchmark is. This command will create a project named Benchmark-master.
The project build process, managed by the maven inside Eclipse, should automatically start and download the
necessary dependencies. When the process is finished, run SpotBugs on the project. The tool should take few
minutes to complete the analysis. When the analysis is finished, open the SpotBugs perspective, which should
display the results. Analyze some examples of injection vulnerabilities to get acquainted with the information
the tool reports about each warning.

Now, analyze the vulnerabilities reported by SpotBugs on the test cases 6, 93, 107, 108, and 148. Which ones
of these test cases is really vulnerable? Which one is not?

| bug     | TP/FP | Reason                                                                                                                                               |
| ------- | ----- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| TC6     | TP    | Untrusted input lead to command injection!                                                                                                           |
| TC93.1  | FP    | Not real vulnerability but still bug to change! (httpOnly)                                                                                           |
| TC93.2  | FP    | Command executed can't be infected by unsanitized input (NO Command injection caused by unsanitized untrusted cookie used as argument for exec call) |
| TC107.1 | FP    | Not real vulnerability but still bug to change! (httpOnly)                                                                                           |
| TC107.2 | FP    | Bad sql statement (non-prepared), but not a vulnerability, since the executed statement is fixed                                                     |
| TC108.1 | FP    | Not real vulnerability but still bug to change! (httpOnly)                                                                                           |
| TC108.2 | TP    | SQL injection caused by unsanitized untrusted cookie used as argument for non-prepared sql statement                                                 |
| TC148   | TP    | Format string and reflected xss are caused by untrusted input!                                                                                       |

#### TC6
```
		String param = "";
		if (request.getHeader("BenchmarkTest00006") != null) {
			param = request.getHeader("BenchmarkTest00006");
		}
		
		// URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
		param = java.net.URLDecoder.decode(param, "UTF-8");

		BenchmarkTest00108
		java.util.List<String> argList = new java.util.ArrayList<String>();
		
		String osName = System.getProperty("os.name");
        if (osName.indexOf("Windows") != -1) {
        	argList.add("cmd.exe");
        	argList.add("/c");
        } else {
        	argList.add("sh");
        	argList.add("-c");
        }
        argList.add("echo " + param);

		ProcessBuilder pb = new ProcessBuilder();

		pb.command(argList);
```
```
This usage of java/lang/ProcessBuilder.command(Ljava/util/List;)Ljava/lang/ProcessBuilder; can be vulnerable to Command Injection
The highlighted API is used to execute a system command. If unfiltered input is passed to this API, it can lead to arbitrary command execution.
```
```
ProcessBuilder().command(argList);
argList = cmd.exe /c or sh -c + param
param = java.net.URLDecoder.decode(param, "UTF-8") (request.getHeader("BenchmarkTest00006"))
UNTRUSTED PARAM!
```
#### TC 93.1, TC93.2
```
	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.setContentType("text/html;charset=UTF-8");
		javax.servlet.http.Cookie userCookie = new javax.servlet.http.Cookie("BenchmarkTest00093", "ls");
		userCookie.setMaxAge(60*3); //Store cookie for 3 minutes
		userCookie.setSecure(true);
		userCookie.setPath(request.getRequestURI());
		userCookie.setDomain(new java.net.URL(request.getRequestURL().toString()).getHost());
		response.addCookie(userCookie);
		javax.servlet.RequestDispatcher rd = request.getRequestDispatcher("/cmdi-00/BenchmarkTest00093.html");
		rd.include(request, response);
	}
```
```
Bug: Cookie without the HttpOnly flag could be read by a malicious script in the browser
A new cookie is created without the HttpOnly flag set. The HttpOnly flag is a directive to the browser to make sure that the cookie can not be red by malicious script. When a user is the target of a "Cross-Site Scripting", the attacker would benefit greatly from getting the session id for example.

Code at risk:

Cookie cookie = new Cookie("email",userName);
response.addCookie(cookie);

Solution (Specific configuration):
Cookie cookie = new Cookie("email",userName);
cookie.setSecure(true);
cookie.setHttpOnly(true); //HttpOnly flag
```
```
@Override
	public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.setContentType("text/html;charset=UTF-8");
	
		javax.servlet.http.Cookie[] theCookies = request.getCookies();
		
		String param = "noCookieValueSupplied";
		if (theCookies != null) {
			for (javax.servlet.http.Cookie theCookie : theCookies) {
				if (theCookie.getName().equals("BenchmarkTest00093")) {
					param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
					break;
				}
			}
		}
		
		
		String bar = "alsosafe";
		if (param != null) {
			java.util.List<String> valuesList = new java.util.ArrayList<String>( );
			valuesList.add("safe");
			valuesList.add( param );
			valuesList.add( "moresafe" );
			
			valuesList.remove(0); // remove the 1st safe value
			
			bar = valuesList.get(1); // get the last 'safe' value
		}
		
		
		String cmd = "";
        String osName = System.getProperty("os.name");
        if (osName.indexOf("Windows") != -1) {
        	cmd = org.owasp.benchmark.helpers.Utils.getOSCommandString("echo");
        }
        
		String[] argsEnv = { "Foo=bar" };
		Runtime r = Runtime.getRuntime();

		try {
			Process p = r.exec(cmd + bar, argsEnv);
			org.owasp.benchmark.helpers.Utils.printOSCommandResults(p, response);
		} catch (IOException e) {
			System.out.println("Problem executing cmdi - TestCase");
			response.getWriter().println(
			  org.owasp.esapi.ESAPI.encoder().encodeForHTML(e.getMessage())
			);
			return;
		}
	}
```
```
Bug: This usage of java/lang/Runtime.exec(Ljava/lang/String;[Ljava/lang/String;)Ljava/lang/Process; can be vulnerable to Command Injection
The highlighted API is used to execute a system command. If unfiltered input is passed to this API, it can lead to arbitrary command execution.
```
```
command, env

Process p = r.exec(cmd + bar, argsEnv);

cmd = "echo"

bar = "alsosafe" OR, `if (param != null)` bar=param

param = "noCookieValueSupplied" OR, `if (request.getCookies()!=null)` && if one 
cookie has name="BenchmarkTest00093", then param= value of the cookie:

COOKIE IS UNTRUSTED! Real vulnerability!

You just need to set cookie with value of "BenchmarkTest00093"="ciao; command to get reverse shell" and you get a sheel on the server!!!

N.B. This would be true if there wasn't this line:

			valuesList.remove(0); // remove the 1st safe value

Since there is this line, even `if (param != null)` bar="moresafe", so there can't be a command execution!

(argsEnv = { "Foo=bar" }) (secure)
```
#### TC107.2
```
	@Override
	public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.setContentType("text/html;charset=UTF-8");
	
		javax.servlet.http.Cookie[] theCookies = request.getCookies();
		
		String param = "noCookieValueSupplied";
		if (theCookies != null) {
			for (javax.servlet.http.Cookie theCookie : theCookies) {
				if (theCookie.getName().equals("BenchmarkTest00107")) {
					param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
					break;
				}
			}
		}
		
		
		// Chain a bunch of propagators in sequence
		String a18521 = param; //assign
		StringBuilder b18521 = new StringBuilder(a18521);  // stick in stringbuilder
		b18521.append(" SafeStuff"); // append some safe content
		b18521.replace(b18521.length()-"Chars".length(),b18521.length(),"Chars"); //replace some of the end content
		java.util.HashMap<String,Object> map18521 = new java.util.HashMap<String,Object>();
		map18521.put("key18521", b18521.toString()); // put in a collection
		String c18521 = (String)map18521.get("key18521"); // get it back out
		String d18521 = c18521.substring(0,c18521.length()-1); // extract most of it
		String e18521 = new String( org.apache.commons.codec.binary.Base64.decodeBase64(
		    org.apache.commons.codec.binary.Base64.encodeBase64( d18521.getBytes() ) )); // B64 encode and decode it
		String f18521 = e18521.split(" ")[0]; // split it on a space
		org.owasp.benchmark.helpers.ThingInterface thing = org.owasp.benchmark.helpers.ThingFactory.createThing();
		String g18521 = "barbarians_at_the_gate";  // This is static so this whole flow is 'safe'
		String bar = thing.doSomething(g18521); // reflection
		
		
		String sql = "SELECT * from USERS where USERNAME='foo' and PASSWORD='"+ bar +"'";
				
		try {
			java.sql.Statement statement =  org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement();
			statement.execute( sql, java.sql.Statement.RETURN_GENERATED_KEYS );
            org.owasp.benchmark.helpers.DatabaseHelper.printResults(statement, sql, response);
		} catch (java.sql.SQLException e) {
			if (org.owasp.benchmark.helpers.DatabaseHelper.hideSQLErrors) {
        		response.getWriter().println(
"Error processing request."
);
        		return;
        	}
			else throw new ServletException(e);
		}
	}
```
```
Bug: org.owasp.benchmark.testcode.BenchmarkTest00107.doPost(HttpServletRequest, HttpServletResponse) passes a nonconstant String to an execute or addBatch method on an SQL statement
The method invokes the execute or addBatch method on an SQL statement with a String that seems to be dynamically generated. Consider using a prepared statement instead. It is more efficient and less vulnerable to SQL injection attacks.

Rank: Troubling (10), confidence: High
Pattern: SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE
Type: SQL, Category: SECURITY (Security)
```
```
statement.execute( sql, java.sql.Statement.RETURN_GENERATED_KEYS );
Non-prepared statement ( java.sql.Statement.RETURN_GENERATED_KEYS just returns automatically the keys generated by the database)
String sql = "SELECT * from USERS where USERNAME='foo' and PASSWORD='"+ bar +"'";
String bar = thing.doSomething(g18521);
thing1.doSomething -> just assign input to return value
thing2.doSomething ->
		if (i == null) return "";
		String r = new StringBuilder(i).toString();
		return r;
String g18521 = "barbarians_at_the_gate";  // This is static so this whole flow is 'safe'
```
#### TC108.2
```
	@Override
	public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.setContentType("text/html;charset=UTF-8");
	
		javax.servlet.http.Cookie[] theCookies = request.getCookies();
		
		String param = "noCookieValueSupplied";
		if (theCookies != null) {
			for (javax.servlet.http.Cookie theCookie : theCookies) {
				if (theCookie.getName().equals("BenchmarkTest00108")) {
					param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
					break;
				}
			}
		}
		
		
		String bar;
		String guess = "ABC";
		char switchTarget = guess.charAt(2);
		
		// Simple case statement that assigns param to bar on conditions 'A', 'C', or 'D'
		switch (switchTarget) {
		  case 'A':
		        bar = param;
		        break;
		  case 'B': 
		        bar = "bobs_your_uncle";
		        break;
		  case 'C':
		  case 'D':        
		        bar = param;
		        break;
		  default:
		        bar = "bobs_your_uncle";
		        break;
		}
		
		
		String sql = "SELECT * from USERS where USERNAME='foo' and PASSWORD='"+ bar +"'";
				
		try {
			java.sql.Statement statement =  org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement();
			statement.execute( sql, new int[] { 1, 2 } );
            org.owasp.benchmark.helpers.DatabaseHelper.printResults(statement, sql, response);
		} catch (java.sql.SQLException e) {
			if (org.owasp.benchmark.helpers.DatabaseHelper.hideSQLErrors) {
        		response.getWriter().println(
"Error processing request."
);
        		return;
        	}
			else throw new ServletException(e);
		}
	}
```
```
Bug: This use of java/sql/Statement.execute(Ljava/lang/String;[I)Z can be vulnerable to SQL injection (with JDBC)
The input values included in SQL queries need to be passed in safely. Bind variables in prepared statements can be used to easily mitigate the risk of SQL injection.

Vulnerable Code:
Connection conn = [...];
Statement stmt = con.createStatement();
ResultSet rs = stmt.executeQuery("update COFFEES set SALES = "+nbSales+" where COF_NAME = '"+coffeeName+"'");

Solution:
Connection conn = [...];
conn.prepareStatement("update COFFEES set SALES = ? where COF_NAME = ?");
updateSales.setInt(1, nbSales);
updateSales.setString(2, coffeeName);
```
```
statement.execute( sql, new int[] { 1, 2 } );
execute(String sql, int[] columnIndexes)
Executes the given SQL statement, which may return multiple results, and signals the driver that the auto-generated keys indicated in the given array should be made available for retrieval.

String sql = "SELECT * from USERS where USERNAME='foo' and PASSWORD='"+ bar +"'";
bar = param
param = noCookieValueSupplied or cookie value if cookie with BenchmarkTest00108 is provided! Untrusted cookie!
```
#### TC148
```
	@Override
	public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.setContentType("text/html;charset=UTF-8");
	
		String param = "";
		if (request.getHeader("Referer") != null) {
			param = request.getHeader("Referer");
		}
		
		// URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
		param = java.net.URLDecoder.decode(param, "UTF-8");
		
		
		String bar;
		
		// Simple if statement that assigns param to bar on true condition
		int num = 196;
		if ( (500/42) + num > 200 )
		   bar = param;
		else bar = "This should never happen"; 
		
		
response.setHeader("X-XSS-Protection", "0");
		Object[] obj = { "a", bar };
		response.getWriter().format("Formatted like: %1$s and %2$s.",obj);
	}
```
```
Bug: This use of java/io/PrintWriter.format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/io/PrintWriter; could be vulnerable to XSS in the Servlet
A potential XSS was found. It could be used to execute unwanted JavaScript in a client's browser. (See references)

Vulnerable Code:

protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    String input1 = req.getParameter("input1");
    [...]
    resp.getWriter().write(input1);
}
Solution:

protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    String input1 = req.getParameter("input1");
    [...]
    resp.getWriter().write(Encode.forHtml(input1));
}
The best defense against XSS is context sensitive output encoding like the example above. There are typically 4 contexts to consider: HTML, JavaScript, CSS (styles), and URLs. Please follow the XSS protection rules defined in the OWASP XSS Prevention Cheat Sheet, which explains these defenses in significant detail.

Note that this XSS in Servlet rule looks for similar issues, but looks for them in a different way than the existing 'XSS: Servlet reflected cross site scripting vulnerability' and 'XSS: Servlet reflected cross site scripting vulnerability in error page' rules in FindBugs.
```
```
response.getWriter().format("Formatted like: %1$s and %2$s.",{ "a", bar });
bar = param preso direttamente dal campo Referer dell'header!
Untrusted input to format string, and reflected xss!
```
### 1.2 Analysis and Fix of the JettyEmbedded project (https://github.com/oktadeveloper/okta-

### spring-boot-jetty-example)

Create an Eclipse project for the JettyEmbedded project (available for your convenience in folder Jettyembed-
ded), by using the ’Open projects from File System’ item from the File menu. The project contains a simple
sample application based on Java servlets. Use SpotBugs to analyse the project code, to look for security vul-
nerabilities, and create a report with your findings. How many true positives (TP) and false positives (FP) did
the tool report? What kind of XSS did you find?


| bug                                         | TP/FP | Reason                 |
| ------------------------------------------- | ----- | ---------------------- |
| 23:Potential XSS                            | TP    | Unsanitized user input |
| 39:Potential XSS                            | TP    | Unsanitized user input |
| 52:Potential XSS                            | TP    | Unsanitized user input |
| 35:Potential XSS                            | TP    | Unsanitized user input |
| 35:HTTP parameter written to Servlet output | TP    | Unsanitized user input |

#### Potential XSS
```
Bug: This use of java/io/PrintWriter.print(Ljava/lang/String;)V could be vulnerable to XSS in the Servlet
A potential XSS was found. It could be used to execute unwanted JavaScript in a client's browser. (See references)

Vulnerable Code:

protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    String input1 = req.getParameter("input1");
    [...]
    resp.getWriter().write(input1);
}
Solution:

protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    String input1 = req.getParameter("input1");
    [...]
    resp.getWriter().write(Encode.forHtml(input1));
}
The best defense against XSS is context sensitive output encoding like the example above. There are typically 4 contexts to consider: HTML, JavaScript, CSS (styles), and URLs. Please follow the XSS protection rules defined in the OWASP XSS Prevention Cheat Sheet, which explains these defenses in significant detail.

Note that this XSS in Servlet rule looks for similar issues, but looks for them in a different way than the existing 'XSS: Servlet reflected cross site scripting vulnerability' and 'XSS: Servlet reflected cross site scripting vulnerability in error page' rules in FindBugs.
```
### HTTP parameter written to Servlet output
```
Bug: HTTP parameter written to Servlet output in com.okta.jettyembedded.HikesTodoServlet.doPost(HttpServletRequest, HttpServletResponse)
This code directly writes an HTTP parameter to Servlet output, which allows for a reflected cross site scripting vulnerability. See http://en.wikipedia.org/wiki/Cross-site_scripting for more information.

SpotBugs looks only for the most blatant, obvious cases of cross site scripting. If SpotBugs found any, you almost certainly have more cross site scripting vulnerabilities that SpotBugs doesn't report. If you are concerned about cross site scripting, you should seriously consider using a commercial static analysis or pen-testing tool.
```
#### 23
```
// Not synchronized
    private List<String> hikes = new ArrayList<>(Arrays.asList(
            "Wonderland Trail", "South Maroon Peak", "Tour du Mont Blanc",
            "Teton Crest Trail", "Everest Base Camp via Cho La Pass", "Kesugi Ridge"
    ));

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws IOException {
        response.getWriter().print(String.join("\n", this.hikes));
    }
```
If hikes can be altered in an untrusted way, then we have an xss.

#### 52
```
    protected void doDelete(HttpServletRequest request, HttpServletResponse response)
        throws IOException {
        String hike = request.getParameter("hike");
        if (hike == null) {
            response.setStatus(400);
            response.getWriter().print("Param 'hike' cannot be null.");
        }
        else {
            this.hikes.remove(hike);
            response.getWriter().print(String.join("\n", this.hikes));
        }
    }
```
If hikes can be altered in an untrusted way, then we have an xss.

#### 35, 39
```
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
        throws IOException {
        String hike = request.getParameter("hike");
        if (hike == null) {
            response.setStatus(400);
            response.getWriter().print("Param 'hike' cannot be null.");
        }
        else if (this.hikes.contains(hike)) {
            response.setStatus(400);
            response.getWriter().print("The hike '"+hike+"' already exists.");
        }
        else {
            this.hikes.add(hike);
            response.getWriter().print(String.join("\n", this.hikes));
        }
    }
```
response.getWriter().print("The hike '"+hike+"' already exists.");

Line 35 is not a vulnerability if the user never added that hike before.

As soon as the user adds a custom hike (untrusted), that is stored, unsanitized into the application memory, and then ALL the other methods (line 35, line 39 print, line 23 get, line 52 delete) becomes xss sinks. For lines 23,39, 52 we have a stored XSS, also since every other user that will execute those requests, will also see whatever the attacker inserted as payload in the memory! For line 35 we have a reflected xss, since the value returned in the response comes directly from the request instead of from the storage (even if it is the same value that is already stored, since this.hike.contains(hike))


Fix the vulnerabilities found in the project, with the aid of the suggestions given by SpotBugs, then run again
the tool and observe how the results of the analysis changed.

1. Download encoder-1.2.3.jar from https://owasp.org/www-project-java-encoder/
2. Add it to build path (referenced libraries)
3. import org.owasp.encoder.*
4. Substitute untrusted strings with: 
	`response.getWriter().print(Encode.forHtml(String.join("\n", this.hikes)));` and `            response.getWriter().print("The hike '"+Encode.forHtml(hike)+"' already exists.");`
	and all the bugs are gone!


### 1.3 Analysis and Fix of vulnerability CVE-2021-

CVE-2021-37573 is a vulnerability of the Tiny Java Web Server and Servlet Container (TJWS,http://tjws.sourceforge.net/). For your convenience, the CVE report is available in the lab material. After having had
a look at it, your task is to find the vulnerability in the Java code of the application, with the help of SpotBugs,
and then fix it. For your convenience, you can find a relevant portion of the code (taken from version 115,
which is the latest one affected by the vulnerability) in the TJWS2 folder, with a pom.xml file that automates
the download of its dependencies and its compilation. This code can be imported into Eclipse as a Maven
Project.

We look for XSS vulnerabilities: 3 potential in CgiServlet.java, 2 potential in FileServlet.java.
| bug             | TP/FP | Reason |
| --------------- | ----- | ------ |
| CgiServlet:181  |       |        |
| CgiServlet:201  |       |        |
| CgiServlet:384  |       |        |
| FileServlet:183 |       |        |
| FileServlet:221 |       |        |

#### CgiServlet:181, 201 (just 1 : of difference)
```java
res.setStatus(Integer.parseInt(tok.nextToken()), tok.nextToken());
tok = new StringTokenizer(line, " "); (with tok.countTokens()==3 && firstLine && no ':')
line = procIn.readLine()
BufferedReader procIn = new BufferedReader(new InputStreamReader(proc.getInputStream()));
Process proc = Runtime.getRuntime().exec(argList, envList); (may be vulnerable to command injection!)
String argList[] = (path + (queryString != null && queryString.indexOf("=") == -1 ? "+" + queryString : "")).split("\\+");
argList and envList untrusted!
This looks like a command injection, which could also maybe lead to reflected xss if the user can execute a command which has an inputStream from which to take the content that will end up in the Status header from the server.
```
#### CgiServlet:384
```
	private void serveDirectory(HttpServletRequest req, HttpServletResponse res, boolean headOnly, String path,
			File file) throws IOException {
		log("indexing " + file);
		if (!file.canRead()) {
			res.sendError(HttpServletResponse.SC_FORBIDDEN);
			return;
		}
		res.setStatus(HttpServletResponse.SC_OK);
		res.setContentType("text/html;charset=" + charSet);
		OutputStream out = res.getOutputStream();
		if (!headOnly) {
			String[] names = file.list();
			if (names == null) {
				res.sendError(HttpServletResponse.SC_FORBIDDEN, "Can't access " + req.getRequestURI());
				return;
			}
```
surprising not this, but:

#### FileServlet:183

```java
Res is a HttpServletResponse.

javax.servlet.http.HttpServlet
protected void service(HttpServletRequest req, HttpServletResponse resp)
     * Receives standard HTTP requests from the public
     * <code>service</code> method and dispatches
     * them to the <code>do</code><i>XXX</i> methods defined in 
     * this class. This method is an HTTP-specific version of the 
     * {@link javax.servlet.Servlet#service} method. There is no
     * need to override this method.
     * 
     * @param resp (res)	the {@link HttpServletResponse} object that
     *			contains the response the servlet returns
     *			to the client				
     
FileServlet
public void service(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException

res.sendError(HttpServletResponse.SC_NOT_FOUND, file.getName()+" not found");

Serve
	// / Writes an error response using the specified status code and
	// message.
	// @param resCode the status code
	// @param resMessage the status message
	// @exception IOException if an I/O error has occurred
	public void sendError(int resCode, String resMessage) throws IOException {
	    setStatus(resCode, resMessage);
	    realSendError();
	}

	private void realSendError() throws IOException {
	    if (isCommitted())
		throw new IllegalStateException("Can not send an error ("+resCode+") - "+resMessage+", headers have been already written");
	    // if (((ServeOutputStream) out).isInInclude()) // ignore
	    // return;
	    setContentType("text/html");
	    StringBuffer sb = new StringBuffer(100);
	    int lsp = resMessage.indexOf('\n');
	    sb.append("<HTML><HEAD>")
		    .append("<TITLE>" + resCode + " " + (lsp < 0 ? resMessage : resMessage.substring(0, lsp))
			    + "</TITLE>").append("</HEAD><BODY " + BGCOLOR)
		    .append("><H2>" + resCode + " " + (lsp < 0 ? resMessage : resMessage.substring(0, lsp)) + "</H2>");
	    if (lsp > 0)
		sb.append("<PRE>").append(Utils.htmlEncode(resMessage.substring(lsp), false)).append("</PRE>");
	    sb.append("<HR>");
	    sendEnd(sb);
	}

File file = new File(filename);
String filename = req.getPathTranslated() != null ? req.getPathTranslated().replace('/', File.separatorChar): "";
public String getPathTranslated() {
    // System.out.println("Path t path i: "+getPathInfo()+", dp: "+dispatchPath);
    return getRequest().getRealPath(getPathInfo());
}
public String getPathTranslated() {
    // In this server, the entire path is regexp-matched against the
    // servlet pattern, so there's no good way to distinguish which
    // part refers to the servlet.
    return getRealPath(getPathInfo());
}
	public String getPathInfo() {
	    // In this server, the entire path is regexp-matched against the
	    // servlet pattern, so there's no good way to distinguish which
	    // part refers to the servlet.
	    return uriLen >= reqUriPath.length() ? null : reqUriPath.substring(uriLen);
	}
    public String getRealPath(String path) {
	//System.err.print("[" + path + "]->[");
	path = Utils.canonicalizePath(path);
	if (path != null && mappingtable != null) {
	    // try find first sub-path
	    Object[] os = mappingtable.get(path);
	    //System.err.println("Searching for path: "+path+" found: "+os[0]);
	    if (os[0] == null)
		return null;
	    int slpos = ((Integer) os[1]).intValue();
	    int pl = path.length();
	    if (slpos > 0) {
		if (path.length() > slpos)
		    path = path.substring(slpos + 1);
		else
		    path = "";
	    } else if (pl > 0) {
		for (int i = 0; i < pl; i++) {
		    char s = path.charAt(i);
		    if (s == '/' || s == '\\')
			continue;
		    else {
			if (i > 0)
			    path = path.substring(i);
			break;
		    }
		}
	    }
	    // System.err.println("Path after processing :"+path+" slash was at "+slpos);
	    return new File((File) os[0], path).getPath(); -> 
	}
	return path;
    }
Bug: This API (java/io/File.<init>(Ljava/io/File;Ljava/lang/String;)V) reads a file whose location might be specified by user input
A file is opened to read its content. The filename comes from an input parameter. If an unfiltered parameter is passed to this file API, files from an arbitrary filesystem location could be read.

This rule identifies potential path traversal vulnerabilities. In many cases, the constructed file path cannot be controlled by the user. If that is the case, the reported instance is a false positive.


The error message will contain the filename passed from untrusted source, unsanitized, and will print it directly, unsanitized!

(The vulnerability (a reflected XSS) can be found in file Acme.Serve.FileServlet.java at line 183: the
filename that is put into the body of the 404 response comes from the path in the request URL. The
vulnerability can be fixed by sanitizing the filename or by checking it before putting it into the response.)

PATCH (https://github.com/drogatkin/TJWS2/compare/v1.115...v1.116):
.append("<TITLE>" + resCode + " " +

(lsp < 0 ? resMessage : resMessage.substring(0, lsp)) -->
Utils.htmlEncode(lsp < 0 ? resMessage : resMessage.substring(0, lsp), false)

+ "</TITLE>").append("</HEAD><BODY " + BGCOLOR)
.append("><H2>" + resCode + " " +

(lsp < 0 ? resMessage : resMessage.substring(0, lsp)) -->
Utils.htmlEncode(lsp < 0 ? resMessage : resMessage.substring(0, lsp), false)

+ "</H2>");

PoC:
HTTP request:
GET /te%3Cimg%20src=x%20onerror=alert(42)%3Est HTTP/1.1

HTTP response:
HTTP/1.1 404 te<img src=x onerror=alert(42)>st not found
```
### 1.4 (Optional) Analysis of a Java project of your choice

If you finished the previous jobs ahead of the end, you can choose an open-source Java project (e.g. from
github) and try to analyse it with SpotBugs. A precondition is that the project can be compiled without errors.

