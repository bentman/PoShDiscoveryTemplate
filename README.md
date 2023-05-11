# PoSh Discovery Report Template

The PoSh Discovery Report Template is a simple framework for automating the process of gathering information by generating standardized text reports in various environments. This template can be used with ChatGPT (or Co-Pilot) to streamline information gathering and produce repeatable reports.

## Key Features

- Simplifies the generation of quick text reports on the logged-in user's desktop.
- Use ChatGPT to customize information gathering snippets with tailored conditions.
- Enhance error control and provide descriptive explanations in snippets.

## Usage Instructions

1. Copy the provided template from the repository.

2. Utilize ChatGPT to interact with the template and store it for later use.  
      ChatGPT-Prompt:> `Store the following as a template to produce snippets "paste content of template between quotes"`

3. Create customized information reporting snippets using the stored template.  
      ChatGPT-Prompt:> `Create a snippet with comments for use with the template that reports "this information"`

4. Add requirements or further enhancements to the snippet.  
      ChatGPT-Prompt:> `If the snippet requires module, check if available and import it if not`

5. Enhance the snippets with appropriate error control.  
      ChatGPT-Prompt:> `Use "SilentlyContinue" and only report errors in the catch block`

6. Get an example of the output for a better understanding.  
      ChatGPT-Prompt:> `Show me an example of the report output`

Make sure to customize the snippets based on your specific environment and requirements.

### GNU General Public License
This script is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This script is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this script.  If not, see <https://www.gnu.org/licenses/>.
