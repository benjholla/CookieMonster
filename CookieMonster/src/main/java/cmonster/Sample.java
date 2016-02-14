package cmonster;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class Sample {
	public static void main(String[] args) throws ClassNotFoundException {
		// load the sqlite-JDBC driver using the current class loader
		Class.forName("org.sqlite.JDBC");

		Connection connection = null;
		try {
			// create a database connection
			connection = DriverManager.getConnection("jdbc:sqlite:" + new File("/Users/benjholla/Desktop/Cookies.db").getAbsolutePath());
			Statement statement = connection.createStatement();
			statement.setQueryTimeout(30); // set timeout to 30 seconds
			ResultSet rs = statement.executeQuery("select * from cookies");
//			ResultSet rs = statement.executeQuery("select * from cookies where host_key like \"%iseage.org%\"");
			while (rs.next()) {
				
				if(rs.getString("host_key").contains("iseage.org")){
					System.out.println("name = " + rs.getString("name"));
				}
				
			}
		} catch (SQLException e) {
			// if the error message is "out of memory",
			// it probably means no database file is found
			System.err.println(e.getMessage());
		} finally {
			try {
				if (connection != null)
					connection.close();
			} catch (SQLException e) {
				// connection close failed.
				System.err.println(e);
			}
		}
	}
}