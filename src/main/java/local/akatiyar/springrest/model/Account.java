/**
 * 
 */
package local.akatiyar.springrest.model;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

/**
 * @author abhinav
 *
 */
@Entity
public class Account {

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private long id;
	
	private String emailAddress;

	public String getEmailAddress() {
		return emailAddress;
	}

	public void setEmailAddress(String emailAddress) {
		this.emailAddress = emailAddress;
	}
	
}
