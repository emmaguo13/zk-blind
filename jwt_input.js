function stringToAsciiArray(str) {
    // Create an empty array to store the ASCII values
    const asciiValues = [];
  
    // Loop through each character in the string
    for (let i = 0; i < str.length; i++) {
      // Get the ASCII value of the current character and add it to the array
      asciiValues.push(str.charCodeAt(i).toString());
    }
  
    // Return the array of ASCII values
    return asciiValues;
  }
  
  // Test the function with a sample string
  console.log(stringToAsciiArray("Hello World!"));  // Outputs: [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33]