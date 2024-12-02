import org.junit.jupiter.api.*;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import static org.junit.jupiter.api.Assertions.*;

public class LoginTest {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/testing";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "`12abc=-0";

//    @Test
//    public void testDatabaseConnection() throws SQLException {
//
//        // Test valid connection
//        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
//        assertNotNull(conn, "Connection should not be null");
//        conn.close();
//
//        // Test invalid credentials
//        SQLException exception = assertThrows(SQLException.class, () -> {
//            DriverManager.getConnection(DB_URL, "root", "123123"); // Invalid password
//        });
//    }

    @Test
    public void testCaseSensitivityForEmailAndPassword() {
        LoginApp app = new LoginApp();

        try {
            // Exact match (correct case)
            String username = app.authenticateUser("johndoe@example.com", "password123");
            assertNotNull(username, "Username should not be null for exact email and password match");
            assertEquals("John Doe", username, "Username should match the expected value for correct credentials");

            // Email case mismatch (should pass)
            username = app.authenticateUser("JOHNDOE@EXAMPLE.COM", "password123"); // Uppercase email
            assertNotNull(username, "Username should not be null for exact email and password match");
            assertEquals("John Doe", username, "Username should match the expected value for correct credentials");

            username = app.authenticateUser("Johndoe@example.com", "password123"); // Mixed-case email
            assertNotNull(username, "Username should not be null for exact email and password match");
            assertEquals("John Doe", username, "Username should match the expected value for correct credentials");

            // Password case mismatch (should pass)
            username = app.authenticateUser("johndoe@example.com", "Password123"); // Capital "P"
            assertNotNull(username, "Username should not be null");
            assertEquals("John Doe", username, "Username should match the expected value for correct credentials");


            // Both email and password case mismatch (should pass)
            username = app.authenticateUser("JOHNDOE@EXAMPLE.COM", "Password123"); // Uppercase email and mismatched password
            assertNotNull(username, "Username should not be null");
            assertEquals("John Doe", username, "Username should match the expected value for correct credentials");

        } catch (Exception e) {
            fail("Not Authenticating Password");
        }
    }



    @Test
    public void testValidEmailAndPassword() {
        LoginApp app = new LoginApp();

        try {
        String username = app.authenticateUser("johndoe@example.com", "password123");
        assertNotNull(username, "Username should not be null for valid email and password");
        assertEquals("John Doe", username, "Username should match the expected value");

        username = app.authenticateUser("alicebrown@example.com", "password101");
        assertNotNull(username, "Username should not be null for valid email and valid password");
        assertEquals("Alice Brown", username, "Username should match the expected value");

        username = app.authenticateUser("mikejohnson@example.com", "password789");
        assertNotNull(username, "Username should not be null for valid email and valid password");
        assertEquals("Mike Johnson", username, "Username should match the expected value");

        username = app.authenticateUser("tomclark@example.com", "password202");
        assertNotNull(username, "Username should not be null for valid email and valid password");
        assertEquals("Tom Clark", username, "Username should match the expected value");
        }
        catch (Exception e){
            fail( "Not Authenticating Password");
        }
    }


    @Test
    public void testInvalidFields() {
        LoginApp app = new LoginApp();

        try {
            //valid password invalid email
            String username = app.authenticateUser("aye@example.com", "password101");
            assertNull(username, "Username should be null for an invalid email");

            username = app.authenticateUser("Mateen@example.com", "password202");
            assertNull(username, "Username should be null for an invalid email");

            //valid email invalid password
            username = app.authenticateUser("janesmith@example.com", "pass");
            assertNull(username, "Username should be null for an invalid password");

            username = app.authenticateUser("tomclark@example.com", "202dad221");
            assertNull(username, "Username should be null for an invalid password");

            //valid email and password but invalid combination
            username = app.authenticateUser("tomclark@example.com", "password789");
            assertNull(username, "Username should be null for an invalid email password combination");

            username = app.authenticateUser("alicebrown@example.com", "password123");
            assertNull(username, "Username should be null for an invalid email password combination");
        }
        catch (Exception e){
            fail( "Not Authenticating Password");
        }
    }


    @Test
    public void testEmptyField() {
        LoginApp app = new LoginApp();

        try {
            //empty fields both
            String username = app.authenticateUser("", "");
            assertNull(username, "Username should be null for an empty email and password");

            //empty email only
            username = app.authenticateUser("", "password123");
            assertNull(username, "Username should be null for an empty email");

            username = app.authenticateUser("", "pass");
            assertNull(username, "Username should be null for an empty email");

            //empty password
            username = app.authenticateUser("janesmith@example.com", "");
            assertNull(username, "Username should be null for an empty password");

            username = app.authenticateUser("janesmith@lhr.nu.edu.com", "");
            assertNull(username, "Username should be null for an empty password");
        }
        catch (Exception e){
            fail( "Not Authenticating Password");
        }
    }

    @Test
    public void testSqlInjection() {
        LoginApp app = new LoginApp();

        //malicious email

        try {
            String userName = app.authenticateUser("johndoe@example.com' OR '1'='1", "password789");
            assertNull(userName, "SQL injection attempt should not return a username");

            userName = app.authenticateUser("alicebrown@example.com' --", "");
            assertNull(userName, "SQL injection attempt should not return a username");

            userName = app.authenticateUser("johndoe@example.com'; Drop Table User; --", "password123");
            assertNull(userName, "SQL injection attempt should not return a username");

            //malicious password
            userName = app.authenticateUser("alicebrown@example.com", "pass OR '1'='1");
            assertNull(userName, "SQL injection attempt should not return a username");

            userName = app.authenticateUser("johndoe@example.com", "password123'; Drop Table User --");
            assertNull(userName, "SQL injection attempt should not return a username");
        }
        catch (Exception e){
            fail( "Not Authenticating Password");
        }
    }
}
