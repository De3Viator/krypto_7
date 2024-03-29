#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

#include <iostream>
#include <vector>
#include <sstream>

struct ECPoint {
    BIGNUM * X;
    BIGNUM * Y;
};
const int CURVE = NID_secp256k1;
EC_GROUP * GROUP = EC_GROUP_new_by_curve_name(CURVE);

ECPoint * ECPoint_gen(BIGNUM * x, BIGNUM * y )  {
    return new ECPoint(x, y);
}

ECPoint * base_point_get() {
    const EC_POINT *point = EC_GROUP_get0_generator(GROUP);

    if (!point) return nullptr;

    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();

    if (!EC_POINT_get_affine_coordinates_GFp(GROUP, point, x, y, nullptr)) {
        BN_free(x);
        BN_free(y);
        return nullptr;
    }
    return new ECPoint{.X =  x, .Y =  y};
}

bool is_on_curve_check(const ECPoint &P) {
    EC_POINT *point = EC_POINT_new(GROUP);
    EC_POINT_set_affine_coordinates(GROUP, point, P.X, P.Y, nullptr);

    int result = EC_POINT_is_on_curve(GROUP, point, nullptr);

    EC_POINT_free(point);
    return result == 1;
}

ECPoint add_EC_points(const ECPoint  * first_point, const ECPoint  * second_point) {
    ECPoint result{};
    result.X = BN_new();
    result.Y = BN_new();

    EC_POINT * pointA = EC_POINT_new(GROUP);
    EC_POINT_set_affine_coordinates(GROUP, pointA, first_point->X, first_point->Y, nullptr);

    EC_POINT * pointB = EC_POINT_new(GROUP);
    EC_POINT_set_affine_coordinates(GROUP, pointB, second_point->X, second_point->Y, nullptr);

    EC_POINT * result_point = EC_POINT_new(GROUP);

    EC_POINT_add(GROUP, result_point ,pointB, pointA, nullptr);
    if (!EC_POINT_get_affine_coordinates_GFp(GROUP, result_point, result.X, result.Y, nullptr)) {
        std::cerr << "Failed to get affine coordinates from result" << std::endl;
        BN_free(result.X);
        BN_free(result.Y);
        EC_POINT_free(pointA);
        EC_POINT_free(pointB);
        return ECPoint{nullptr, nullptr};
    }
    return result;
}

ECPoint double_EC_point(const ECPoint &a) {
    ECPoint result{};
    result.X = BN_new();
    result.Y = BN_new();

    EC_POINT * doubled_point = EC_POINT_new(GROUP);
    EC_POINT_set_affine_coordinates(GROUP, doubled_point, a.X, a.Y, nullptr);

    EC_POINT * result_point = EC_POINT_new(GROUP);
    EC_POINT_dbl(GROUP, result_point, doubled_point, nullptr);
    if (!EC_POINT_get_affine_coordinates_GFp(GROUP, result_point, result.X, result.Y, nullptr)) {
        std::cerr << "Failed to get affine coordinates from result" << std::endl;
        BN_free(result.X);
        BN_free(result.Y);
        EC_POINT_free(doubled_point);
        return ECPoint{nullptr, nullptr};
    }
    EC_POINT_free(doubled_point);
    return result;
}

ECPoint scalar_mult(const BIGNUM * k, const ECPoint &a) {
    ECPoint result{};
    result.X = BN_new();
    result.Y = BN_new();

    EC_POINT * pointA = EC_POINT_new(GROUP);
    EC_POINT * result_point = EC_POINT_new(GROUP);
    EC_POINT_set_affine_coordinates_GFp(GROUP, pointA, a.X, a.Y, nullptr);
    EC_POINT_mul(GROUP, result_point, nullptr, pointA, k, nullptr);

    if (!EC_POINT_get_affine_coordinates_GFp(GROUP, result_point, result.X, result.Y, nullptr)) {
        BN_free(result.X);
        BN_free(result.Y);
        EC_POINT_free(pointA);
        return ECPoint{nullptr, nullptr};
    }
    EC_POINT_free(pointA);
    return result;
}
std::string EC_point_to_string (ECPoint point) {
    return std::string(BN_bn2dec(point.X)) + ',' + std::string(BN_bn2dec(point.Y)) ;
}

ECPoint string_to_EC_point(const std::string &s) {
    ECPoint result{};
    result.X = BN_new();
    result.Y = BN_new();

    size_t pos = s.find(',');
    std::string x_str = s.substr(0, pos);
    std::string y_str = s.substr(pos + 1);

    BN_dec2bn(&result.X, x_str.c_str());
    BN_dec2bn(&result.Y, y_str.c_str());
    return result;
}

void print_EC_point(ECPoint point) {
    std::cout<<"X: "<<BN_bn2dec(point.X)<<std::endl;
    std::cout<<"Y: "<<BN_bn2dec(point.Y)<<std::endl;
}

bool are_EC_points_equal(const ECPoint &point1, const ECPoint &point2) {
    return (BN_cmp(point1.X, point2.X) == 0) && (BN_cmp(point1.Y, point2.Y) == 0);
}


int main() {
    BIGNUM *k = BN_new();
    BIGNUM *d = BN_new();
    BN_set_word(k,15);
    BN_set_word(d,15);
    ECPoint * G = base_point_get();
    if(G) {
        ECPoint H1 = scalar_mult(d, *G);
        ECPoint H2 = scalar_mult(k, H1);
        ECPoint H3 = scalar_mult(k, *G);
        ECPoint H4 = scalar_mult(d, H3);

        if(are_EC_points_equal(H2, H4)) std::cout<<"These values are similar";
        else std::cout<<"These values aren't similar";
    }
    return 0;
}
