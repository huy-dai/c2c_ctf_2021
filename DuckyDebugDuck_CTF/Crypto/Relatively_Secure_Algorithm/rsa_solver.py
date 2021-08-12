# Solves multi prime rsa given n, e, and c. Need to factor n into primes first (recommend yafu)
# Reference https://crypto.stackexchange.com/questions/31109/rsa-enc-decryption-with-multiple-prime-modulus-using-crt
# From https://github.com/diogoaj/ctf-writeups/tree/master/2018/Timisoara/crypto/NotYourAverageRSA

import binascii

# Params
e = 65537
c = 24715967685667908755682143552558301228895312856211439254751278856867878822964565163534510469936883475207381551974263121288818638815590209829046605705934884999799688011188009729082903829082870627331532547086642464951949279593609910113030150833000695261470152359233914523508358790960728100932841856192486816774999547660137998025855054463626455166680450815005634311609262714477388320655298195005372476666536344433868302715671653367396357979323660932473642853195202942908928916112439518280638675390127960040234256408831855808991407641499245314300208714360285350544849965807918228311619616815547521337911167590562212366417466162226443285490382429794073515122796613960489756521974327788417877937398348904790717154292050633465186458177127847198714850112602023951651380018700866140645706146487547682120601474189742409942928804526991649478343057631302061542546856756336249425712037804186270745139317426342565606602358076267515330051294412355034202584625120525189906061509752862456253790575835529817600288958034138055806341374192687343961164073740105171251649685229987579568602088627287970037488651160912111961547302445627842762654485495100388400925879614578755424340717930964599631708087549274389877839616079093186662873897681760959522420756566179048190110035556928426843206576658026137330265525476055769521706260856523778437320323643528914761561220779422057582174267224786127758596199130903736855530483273104550604941266288619364648307969406683695314328473918200752704899649476756898042631730322277193245007417103723086092182980256619512655253112468
n = 64688515842284381671285004713804057636974557043123767909276429885604529285055404207075465905227143695430455279800518929093831790936189708370062485183802100838287376867856559903530579349374796297159049065333233931788848350374173712353230060293523474403987407765649434254998522278378495084980700748935618891923962239344544154272491020249558215375977606486760460422202116533788408155245251359521777496616339405771279249068498668116863069351420020125562376739789157649944067345626979176860652958691999120437343723606888389461284256787402625251235241451411378545300689504397171479953543369035178883526250835923703615578136066684839630468512969083190896398779217095068726488419589358409070454386485844997512703281268502500904561738131008765847551172137972586469740509371675414288404281022456568352136696484283422736887811386820703315621810671355735245976200449110198324297579063662473065418084750048169016026532746592187197223016440024737743946165469032386005490490777351422019715144641826330155082800871042763249387422682239874216066638266888151007585252882687342656759731162027247188605648618213032769015693624797403843186368832529467616755553007077348968460557923432409793346685045600037583739794581285620144710211799130766036576699501229814477038586532407516082567813449345012514324236599197601215293935631469950279433487156213490137438955911443975101487007277541610916632919492197556190435604801295384189903757992369143122734749876437785266527123465057030823398306626678265572569955990069442076473575637262453172104176942861509829663820711953
# primes are factored from n
primes = [130253533329098596570420520808720362179833063923690882802031588080258681875597891614968648643195932708388720998097153616637408009257749598852569059547968696067531823769374723353383546361479031981926664537122286212390453103707103373545875908752360174206997387932395859288222286270776938404587313545445699240561,
            137148322605253893405601071647989147473012366204578150318570681490388076608290415241046400201318980756631821126613469760073196396538065688527242807499955046671343380364155919195748923723647796489887335116902579318331448471191710399991547592678092064744586412553355830084654620577595729759023982602222679230011,
            138515385804373170397818358868362031862224620127307607236864891947194541672679256296075925887732697226315440647186101334166305030839594788559187432089929956346018714244755204705758627968009585464014648513969515351256012552605853517637584763771415842057949523386227581913523074176477900131782899622885925121211,
            146352803736460431152682780930448528333995667230027630119530674746168969150072031573100646406265860922920281662978647092283211889308875630087325353848412172877287708932541373994744014548437761028099893433789255786745319319494805279501455662792859750374838650778693226149324549652195002525197979597932790644303,
            178627414022386986884508122207287255098587217469357848478653245997485108019850766923825107710132126547194666486904259771028311674179759016235834791178967559765615654402252842547982978103104261934361116627388043063841055915766884971618624335701351234982418965964686951852727527049115486477403832482125390304871]

n = 174776634499365185044152993509362624036904353007427805459068176329835550069164957428014245129075350521665501113613732156274308708416158135093542590677545505977327257686941870374910044600757349485405575480034556717469583373661251050825191173966631184463407966953014469657004165922729869240061652972104818333329
e = 65537
p = 13220311437306051037966153711856858730980155743517642596833982288504794306032205070914072726758118520978501154561694973924426687814544691058721727225563177

primes = [p,p]

def egcd(a, b):
    '''
    Helper function for `modinv`.
    Implements the Extended Euclidean Algorithm (source: https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/)
    to get ax + by = gcd(a,b) and uses that equation to get
    result for modular inverse of a mod b.
    '''
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    '''
    Given a value `a` and `m`, find the modular inverse such that
    mod_inverse * a = 1 (mod m)
    '''
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

#The following is implementation of the RSA decryption process as 
#described in the reference StackOverflow post

ts = []
xs = []
ds = []

#Calculate d_i terms
for i in range(len(primes)):
	ds.append(modinv(e, primes[i]-1))

#Calculate t_i terms
m = primes[0]

for i in range(1, len(primes)):
	ts.append(modinv(m, primes[i]))
	m = m * primes[i]

#Calculate x_i terms
#Uses pow for fast a^b mod c calculations
for i in range(len(primes)):
	xs.append(pow((c%primes[i]), ds[i], primes[i]))

#Combine induvidual prime factor results and uses them to decrypt the message
x = xs[0]
m = primes[0]

for i in range(1, len(primes)):
	x = x + m * ((xs[i] - x % primes[i]) * (ts[i-1] % primes[i]))
	m = m * primes[i]

#Format result as hex and then decode it into ASCII
print(binascii.unhexlify(hex(x%n)[2:]))