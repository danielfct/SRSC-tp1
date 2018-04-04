package stgc_tlp;

public class Ciphersuite {
	
	private String algorithm;
	private String mode;
	private String padding;
	
	
	public Ciphersuite(String algorithm, String mode, String padding) {
		this.algorithm = algorithm;
		this.mode = mode;
		this.padding = padding;
	}
	
	public Ciphersuite(String transformation) {
		String[] t = transformation.split("/");
		if (t.length != 3) {
			throw new IllegalArgumentException("Transformation must be of type algorithm/mode/padding");
		}
		this.algorithm = t[0];
		this.mode = t[1];
		this.padding = t[2];
	}
	
	public String getAlgorithm() {
		return algorithm;
	}
	
	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}
	
	public String getMode() {
		return mode;
	}
	
	public void setMode(String mode) {
		this.mode = mode;
	}
	
	public String getPadding() {
		return padding;
	}
	
	public void setPadding(String padding) {
		this.padding = padding;
	}
	
	public String getTransformation() {
		return algorithm + "/" + mode + "/" + padding;
	}
	
	@Override
	public String toString() {
		return getTransformation();
	}

}