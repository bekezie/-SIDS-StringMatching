import java.util.*;
public class RSA
{
    // number of characters in the input alphabet
    public final static int d = 256;

    /*
        pat = pattern we're trying to match to
        txt = text to search
        q = prime number
        h,p,t = values used for hashing
    */
    static void search(String pat, String txt, int q)
    {
        int m = pat.length();
        int n = txt.length();
        int i, j;
        int p = 0; // hash value for pattern
        int t = 0; // hash value for file
        int h = 1;

        // The value of h would be "pow(d, m-1)%q"
        for (i = 0; i < m-1; i++)
            h = (h*d)%q;

        // Calculates the hash value for pattern/signature and txt/file
        for (i = 0; i < m; i++)
        {
            p = (d*p + pat.charAt(i))%q;
            t = (d*t + txt.charAt(i))%q;
        }

        // Slide the pattern over txt one by one
        for (i = 0; i <= n - m; i++)
        {

            // Check the hash values of current window of text
            // and pattern. If the hash values match then only
            // check for characters on by one
            if ( p == t )
            {
                /* Check for characters one by one */
                for (j = 0; j < m; j++)
                {
                    if (txt.charAt(i+j) != pat.charAt(j))
                        break;
                }

                // if p == t and pat[0...m-1] = txt[i, i+1, ...i+m-1]
                if (j == m)
                    System.out.println("Alert! Malicious threat " + pat + " found at index " + i + " in " + txt + ".");
            }

            // Calculate hash value for next window of text: Remove
            // leading digit, add trailing digit
            if ( i < n-m )
            {
                t = (d*(t - txt.charAt(i)*h) + txt.charAt(i+m))%q;

                // We might get negative value of t, converting it
                // to positive
                if (t < 0)
                    t = (t + q);
            }
        }
    }


    public static void main(String[] args)
    {
        Scanner sc = new Scanner(System.in);
        System.out.println("We have a list of files from 1 - 9 that you can send to a host.");
        System.out.println();
        System.out.println("You will select 1 of the 9 files.");
        System.out.println();
        System.out.println("The selected file will be matched/compared");
        System.out.println("to the known signatures in database.");
        System.out.println();
        System.out.println("If there is a match there will be an alert displayed that you have");
        System.out.println("a malicious threat with the following hex values in your file.");
        System.out.println();


        //file with possible threats
        String txt = null;

        // known signature in database
        String[] pat = {"daa", "bkr", "tuo", "ovb","jsk","vbv","xvi","gifh","scb"};


        // A prime number
        int q = 101;

        while(true){
            System.out.println("Select a file from 1 - 9");
            int select = sc.nextInt();
            if(select == 1){
                txt = "gfhdbscbdaa";
            }
            if(select == 2){
                txt = "acbvnbkrhwhs";
            }
            if(select == 3){
                txt = "erytuodfba";
            }
            if(select == 4){
                txt = "ovbvxcsgd";
            }
            if(select == 5){
                txt = "tgjskdgjska";
            }
            if(select == 6){
                txt = "pnvbvhdgsg";
            }
            if(select == 7){
                txt = "axzxvibigfr";
            }
            if(select == 8){
                txt = "ngifhdgssis";
            }
            if(select == 9){
                txt = "gfhdbscbdaa";
            }

            System.out.println();



            for(int i = 0; i < pat.length;i++){
                // Search Call
                search(pat[i], txt, q);
            }

            System.out.println();

            System.out.println("Do you want to end program? Enter 0 to end program.To continue enter any integer besides 0.");
            int exit = sc.nextInt();
            if(exit == 0){
                break;
            }


        }
        System.out.println("Program terminated. Goodbye.");







    }
}



