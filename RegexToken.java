//    CSRF Scanner Extension for Burp Suite
//    Copyright (C) 2017  Adrian Hayter
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program.  If not, see <http://www.gnu.org/licenses/>.

package burp;

import java.io.IOException;
import java.io.Serializable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RegexToken extends Token implements Serializable
{
    private Pattern pattern;
    private transient Matcher matcher; // Matcher cannot be serialized.
    
    public RegexToken(String value, boolean caseSensitive)
    {
        super(value, caseSensitive);
        
        if (caseSensitive)
        {
            pattern = Pattern.compile(value);
        }
        else
        {
            pattern = Pattern.compile(value, Pattern.CASE_INSENSITIVE);
        }

        matcher = pattern.matcher("");
    }
    
    private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();
        this.matcher = this.pattern.matcher(""); // Create new instance of matcher when object is deserialized.
    }
    
    @Override public int getMatchType()
    {
        return 1;
    }
    
    public Matcher getMatcher()
    {
        return this.matcher;
    }
    
    @Override public boolean matches(String s)
    {
        matcher.reset(s);
        
        return matcher.matches();
    }
}
