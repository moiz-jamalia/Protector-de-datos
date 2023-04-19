package kleinprojekt;

public class Regex {
	
	private String regex0 = "/^[^a-zA-Z]{2,10}$/";
	private String regex1 = "/^(?=.*[A-Za-z])(?=.*\\d)(?=.*[@$!%|*?&+-])[A-Za-z\\d@$!%|*?&+-]{8,}$/";
	private String regex2 = "/^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%|*?&+-])[A-Za-z\\d@$!%|*?&+-]{8,}$/";
	private String regex3 = "/^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%|*?&+-])[A-Za-z\\d@$!%|*?&+-]{12,}$/";
	private String regex4 = "/^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%|*?&+-])[A-Za-z\\d@$!%|*?&+-]{16,}$/";
	
	public String getRegex0() {
		return regex0;
	}
	
	public String getRegex1() {
		return regex1;
	}

	public String getRegex2() {
		return regex2;
	}

	public String getRegex3() {
		return regex3;
	}

	public String getRegex4() {
		return regex4;
	}
	
	
}
