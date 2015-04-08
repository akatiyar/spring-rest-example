/**
 * 
 */
package local.akatiyar.springrest.service;

import java.util.List;

import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import local.akatiyar.springrest.model.Account;

/**
 * @author abhinav
 *
 */
@RepositoryRestResource(collectionResourceRel = "accounts", path = "accounts")
public interface AccountRepository extends
		PagingAndSortingRepository<Account, Long> {

	List<Account> findByEmailAddress(@Param("email") String emailAddress);
}
