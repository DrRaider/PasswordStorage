package PasswordStorage;

import static PasswordStorage.HMAC_MD5.hmac;
import static PasswordStorage.MD5.*;

public class Main {
    public static void main(String[] args) {

        System.out.println("HMAC :");
        hmac("what do ya want for nothing?", "Jefe");

        String[] password = {
                "a", "deserted", "relation", "vivacious", "vast", "slave", "attach", "mature", "fork",
                "tremendous", "teeny", "sulky", "unique", "grease", "torpid", "debonair", "calculating",
                "inject", "compare", "twist", "talented", "serve", "sleet", "cycle", "ritzy", "imminent",
                "scrub", "ripe", "wealth", "aloof", "scintillating", "wealthy", "notebook", "laborer",
                "notice", "treat", "answer", "leather", "vigorous", "milk", "flower", "oven", "fry",
                "outstanding", "scatter", "bumpy", "rinse", "savory", "average", "violent", "relieved",
                "kindly", "post", "lunch", "attractive", "chalk", "ajar", "seashore", "fast", "hissing",
                "sneeze", "comfortable", "yielding", "nervous", "permissible", "eggnog", "rigid", "kettle",
                "chubby", "trousers", "quizzical", "screw", "hilarious", "fasten", "holiday", "hammer",
                "moor", "elbow", "staking", "kiss", "unarmed", "yawn", "woebegone", "place", "welcome",
                "drain", "kick", "depend", "tightfisted", "cheat", "deceive", "striped", "number",
                "macabre", "train", "alluring", "oafish", "stitch", "honey", "attend"
        };

        System.out.println("\nMD5 :");
        md5(password);

        System.out.println("\nWith salt :");
        md5Salted(password);
    }

}
