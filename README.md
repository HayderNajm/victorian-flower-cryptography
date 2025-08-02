# Victorian Flower Cryptography

A Python project that combines Victorian floriography with modern block cipher cryptography to send secret messages encoded in flower bouquets.

## Features

- Uses the PRESENT lightweight block cipher for encryption
- Maps encrypted messages to Victorian flower arrangements
- Interactive command-line interface for creating and decoding bouquets
- Includes a comprehensive Victorian flower dictionary
- Cryptographically secure random number generation

## How It Works

1. **Encryption**: Your secret message is encrypted using the PRESENT block cipher
2. **Flower Mapping**: The encrypted data is converted into a sequence of flowers using nibble encoding
3. **Bouquet Creation**: The flowers are arranged into a bouquet that can be shared
4. **Decoding**: The recipient uses the decryption key to convert the flowers back into the original message

## Installation

No external libraries required! This project uses only Python's standard library.

After Run 




🔐 SECURE VICTORIAN FLOWER CRYPTOGRAPHY 🔐
Combining 19th-century floriography with PRESENT block cipher


Main Menu:
1. Create a secret message bouquet
2. Decode a secret message from a bouquet
3. View flower dictionary
4. Generate a secure key
5. View cipher information
6. Exit

Enter your choice (1-6): 1

==================================================
CREATE A SECRET MESSAGE BOUQUET
==================================================

Enter your secret message: hi, Im hayder this is my first project on github

Key options:
1. Generate a secure random key
2. Provide my own key (10 bytes in base64)
Enter your choice (1-2): 1

==================================================
SECURE KEY GENERATION
==================================================
Generated Key (hex): b0b9fb87a3fc0a835c4b
Key Length: 80 bits
Key Entropy: 80 bits (maximum for this key size)

Key Randomness Verification:
Chi-squared statistic: 246.00
⚠ Key may not have sufficient randomness

Generated key (base64): sLn7h6P8CoNcSw==

🌸 VICTORIAN SECRET BOUQUET 🌸
========================================
1. Pink Rose - Grace, admiration
2. Hyacinth (purple) - Sorrow, regret
3. Gardenia - Secret love
4. Forget-me-not - True love, memories
5. White Rose - Purity, innocence
6. Pink Rose - Grace, admiration
7. Lily of the Valley - Return of happiness
8. Sunflower - Adoration, loyalty
9. Zinnia - Thoughts of absent friends
10. Ivy - Fidelity, marriage
11. Ivy - Fidelity, marriage
12. Forget-me-not - True love, memories
13. Hyacinth (purple) - Sorrow, regret
14. Ivy - Fidelity, marriage
15. White Rose - Purity, innocence
16. Tulip (red) - Declaration of love
17. Gardenia - Secret love
18. Gardenia - Secret love
19. Yellow Rose - Friendship, jealousy
20. Yellow Rose - Friendship, jealousy
21. Gardenia - Secret love
22. Yellow Rose - Friendship, jealousy
23. Lily of the Valley - Return of happiness
24. Ivy - Fidelity, marriage
25. Ivy - Fidelity, marriage
26. Pink Rose - Grace, admiration
27. Pink Rose - Grace, admiration
28. Lavender - Devotion
29. Hyacinth (purple) - Sorrow, regret
30. Red Rose - Love, passion
31. Pink Rose - Grace, admiration
32. Lily of the Valley - Return of happiness
33. Sunflower - Adoration, loyalty
34. Violet - Faithfulness, modesty
35. Hyacinth (purple) - Sorrow, regret
36. Forget-me-not - True love, memories
37. Yellow Rose - Friendship, jealousy
38. Hyacinth (blue) - Constancy
39. Red Rose - Love, passion
40. Lily of the Valley - Return of happiness
41. White Rose - Purity, innocence
42. Violet - Faithfulness, modesty
43. Lavender - Devotion
44. Zinnia - Thoughts of absent friends
45. Zinnia - Thoughts of absent friends
46. Violet - Faithfulness, modesty
47. Hyacinth (blue) - Constancy
48. Pink Rose - Grace, admiration
49. Forget-me-not - True love, memories
50. Violet - Faithfulness, modesty
51. Sweet Pea - Goodbye, departure
52. Lily of the Valley - Return of happiness
53. Hyacinth (purple) - Sorrow, regret
54. Zinnia - Thoughts of absent friends
55. Yellow Rose - Friendship, jealousy
56. Hyacinth (blue) - Constancy
57. Forget-me-not - True love, memories
58. Red Rose - Love, passion
59. Zinnia - Thoughts of absent friends
60. White Rose - Purity, innocence
61. Hyacinth (purple) - Sorrow, regret
62. Red Rose - Love, passion
63. White Rose - Purity, innocence
64. Sunflower - Adoration, loyalty
65. Red Rose - Love, passion
66. Red Rose - Love, passion
67. Hyacinth (blue) - Constancy
68. White Rose - Purity, innocence
69. Tulip (red) - Declaration of love
70. White Rose - Purity, innocence
71. Lavender - Devotion
72. Violet - Faithfulness, modesty
73. Zinnia - Thoughts of absent friends
74. Pink Rose - Grace, admiration
75. White Rose - Purity, innocence
76. Ivy - Fidelity, marriage
77. Sunflower - Adoration, loyalty
78. Zinnia - Thoughts of absent friends
79. Sweet Pea - Goodbye, departure
80. Red Rose - Love, passion
81. Sweet Pea - Goodbye, departure
82. Red Rose - Love, passion
83. Ivy - Fidelity, marriage
84. Hyacinth (purple) - Sorrow, regret
85. Lavender - Devotion
86. Hyacinth (blue) - Constancy
87. Sweet Pea - Goodbye, departure
88. Zinnia - Thoughts of absent friends
89. White Rose - Purity, innocence
90. Hyacinth (blue) - Constancy
91. White Rose - Purity, innocence
92. Yellow Rose - Friendship, jealousy
93. Ivy - Fidelity, marriage
94. Zinnia - Thoughts of absent friends
95. Zinnia - Thoughts of absent friends
96. Gardenia - Secret love
97. Yellow Rose - Friendship, jealousy
98. Sunflower - Adoration, loyalty
99. Hyacinth (blue) - Constancy
100. Sunflower - Adoration, loyalty
101. Pink Rose - Grace, admiration
102. Hyacinth (blue) - Constancy
103. Red Rose - Love, passion
104. Hyacinth (purple) - Sorrow, regret
105. Hyacinth (purple) - Sorrow, regret
106. Hyacinth (purple) - Sorrow, regret
107. Hyacinth (blue) - Constancy
108. Gardenia - Secret love
109. Violet - Faithfulness, modesty
110. White Rose - Purity, innocence
111. Zinnia - Thoughts of absent friends
112. White Rose - Purity, innocence
========================================
Secret Message: hi, Im hayder this is my first project on github


Decryption Key: sLn7h6P8CoNcSw==

Testing decryption...
Decoded message: hi, Im hayder this is my first project on github
