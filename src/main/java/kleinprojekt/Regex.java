package kleinprojekt;

public class Regex implements IRegex {

	/**
	 * Just a test-regex for development (minimum 3 & maximum 10 characters, no whitespaces)
	 */
	@Override
	public String regex0() {
		return "/^.[^\\s]{2,10}$/";
	}

	/**
	 * Minimum eight characters, at least one letter, one number and one special character
	 */
	@Override
	public String regex1() {
		return "/^(?=.*[A-Za-z])(?=.*\\d)(?=.*[@$!%|*?&+-])[A-Za-z\\d@$!%|*?&+-]{8,}$/";
	}

	/**
	 * Minimum eight characters, at least one uppercase letter, one lowercase letter, one number and one special character
	 */
	@Override
	public String regex2() {
		return "/^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%|*?&+-])[A-Za-z\\d@$!%|*?&+-]{8,}$/";
	}

	/**
	 * Minimum twelve characters, at least one uppercase letter, one lowercase letter, one number and one special character
	 */
	@Override
	public String regex3() {
		return "/^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%|*?&+-])[A-Za-z\\d@$!%|*?&+-]{12,}$/";
	}

	/**
	 *  Minimum sixteen characters, at least one uppercase letter, one lowercase letter, one number and one special character
	 */
	@Override
	public String regex4() {
		return "/^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%|*?&+-])[A-Za-z\\d@$!%|*?&+-]{16,}$/";
	}
}